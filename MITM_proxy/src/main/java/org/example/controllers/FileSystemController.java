package org.example.controllers;

import org.example.config.ProxyConfig;
import org.example.services.StorageService;
import org.example.services.StorageServiceFactory;
import org.example.services.VaultService;
import org.example.services.EncryptionService;
import org.example.services.StorageMetricsComparisonService;
import org.example.entities.FileInfo;
import org.example.model.StorageMetrics;
import org.apache.hadoop.fs.StorageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.InputStreamResource;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.time.Instant;

@Controller
@RequestMapping("/files")
public class FileSystemController {

    private static final Logger logger = LoggerFactory.getLogger(FileSystemController.class);
    private static final long LARGE_FILE_THRESHOLD = 10 * 1024 * 1024; // 10MB

    @Autowired
    private StorageServiceFactory storageServiceFactory;

    @Autowired
    private VaultService vaultService;


    @Autowired
    private StorageMetricsComparisonService metricsComparisonService;

    @Autowired
    private ProxyConfig proxyConfig;

    @GetMapping
    public String index(Model model) {
        Map<String, Object> metrics = storageServiceFactory.getStorageService().getMetrics();
    
        // Add performance metrics
        model.addAttribute("totalOperations", metrics.getOrDefault("total_operations", 0));
        model.addAttribute("averageTime", metrics.getOrDefault("average_time", 0.0));
        model.addAttribute("successRate", metrics.getOrDefault("success_rate", 0.0));
        
        // Add system metrics
        model.addAttribute("throughput", metrics.getOrDefault("throughput_ops", "0.00"));
        model.addAttribute("dataRead", metrics.getOrDefault("data_read_kb", "0.00"));
        model.addAttribute("dataWritten", metrics.getOrDefault("data_written_kb", "0.00"));
        model.addAttribute("cpuUsage", metrics.getOrDefault("cpu_usage", "0.00"));
        model.addAttribute("memoryUsage", metrics.getOrDefault("memory_usage", "0.00"));
        model.addAttribute("nonHeapMemory", metrics.getOrDefault("non_heap_memory_mb", "0.00"));
        
        // Get list of files
        List<FileInfo> files = storageServiceFactory.getStorageService().listFiles();
        if (files == null) {
            files = new ArrayList<>();
        }
        
        // Add storage service information
        String storageType = proxyConfig.getStorageType();
        model.addAttribute("storageType", storageType);
        model.addAttribute("fileCount", files.size());
        model.addAttribute("files", files);
        
        return "filesystem";
    }

    @ResponseBody
    @GetMapping("/api/files")
    public List<FileInfo> listFiles() {
        logger.info("Listing files from storage service");
        List<FileInfo> files = storageServiceFactory.getStorageService().listFiles();
        logger.info("Found {} files in storage", files.size());
        
        List<FileInfo> filesWithMetadata = new ArrayList<>();
        for (FileInfo file : files) {
            if (file.getName() == null) {
                logger.warn("Skipping file with null name");
                continue;
            }
            
            logger.info("Processing file with name: {}", file.getName());
            try {
                Map<String, Object> metadata = vaultService.getMetadata(file.getName());
                if (metadata != null) {
                    String originalFilename = (String) metadata.get("originalFilename");
                    long fileSize = ((Number) metadata.getOrDefault("size", 0L)).longValue();
                    long timestamp = ((Number) metadata.getOrDefault("timestamp", 0L)).longValue();
                    
                    logger.info("Found metadata for file name {}: originalFilename={}, size={}, timestamp={}", 
                        file.getName(), originalFilename, fileSize, timestamp);
                    
                    filesWithMetadata.add(new FileInfo(
                        originalFilename != null ? originalFilename : file.getName(),
                        fileSize,
                        Instant.ofEpochMilli(timestamp),
                        false
                    ));
                } else {
                    logger.warn("No metadata found for file name: {}", file.getName());
                    filesWithMetadata.add(file);
                }
            } catch (Exception e) {
                logger.error("Error processing file name: {}", file.getName(), e);
                filesWithMetadata.add(file);
            }
        }
        
        logger.info("Returning {} files with metadata", filesWithMetadata.size());
        return filesWithMetadata;
    }

    @PostMapping(value = "/api/files/upload")
    @ResponseBody
    public Map<String, Object> uploadFile(
            @RequestParam(value = "file", required = false) MultipartFile file,
            HttpServletRequest request) {

        Map<String, Object> response = new HashMap<>();
        try {
            String contentType = request.getContentType();
            logger.info("Received upload request with content type: {}", contentType);

            // Direct octet-stream (large upload)
            if (contentType != null && contentType.toLowerCase().contains("application/octet-stream")) {
                logger.info("Handling direct stream upload");
                return handleDirectUpload(request);
            }

            // Standard multipart upload
            if (file == null || file.isEmpty()) {
                logger.warn("No file provided or file is empty");
                response.put("success", false);
                response.put("message", "No file provided or file is empty");
                return response;
            }

            String originalFilename = file.getOriginalFilename();
            logger.info("Starting upload for file: {} ({} bytes)", originalFilename, file.getSize());

            // Use the original filename as the fileId
            String fileId = originalFilename;
            logger.info("Using fileId: {}", fileId);

            // Store the file
            boolean success = storageServiceFactory.getStorageService().storeFileStreaming(fileId, file.getInputStream());
            logger.info("File storage result: {}", success);
            
            // if (success) {
            //     // Store metadata in Vault
            //     Map<String, Object> metadata = new HashMap<>();
            //     metadata.put("fileId", fileId);
            //     metadata.put("originalFilename", originalFilename);
            //     metadata.put("size", file.getSize());
            //     metadata.put("timestamp", System.currentTimeMillis());
            //     metadata.put("isEncrypted", true);
                
            //     try {
            //         logger.info("Storing metadata in Vault for fileId: {}", fileId);
            //         vaultService.storeMetadata(fileId, metadata);
            //         logger.info("Successfully stored metadata for fileId: {}", fileId);
            //     } catch (Exception e) {
            //         logger.error("Failed to store metadata for fileId: {}", fileId, e);
            //         // Don't fail the upload if metadata storage fails
            //     }
            // }
            
            response.put("success", success);
            response.put("fileId", fileId);
            response.put("originalFilename", originalFilename);
            response.put("size", file.getSize());
            response.put("message", success ? "File uploaded successfully" : "Failed to store file");

            logger.info("Upload completed for file: {}", originalFilename);
            return response;

        } catch (Exception e) {
            logger.error("Upload failed", e);
            response.put("success", false);
            response.put("message", e.getMessage());
            return response;
        }
    }

    private Map<String, Object> handleDirectUpload(HttpServletRequest request) throws Exception {
        Map<String, Object> result = new HashMap<>();
        String originalFilename = request.getHeader("X-File-Name");
        logger.info("Starting direct stream upload for: {}", originalFilename);
        
        if (originalFilename == null || originalFilename.trim().isEmpty()) {
            logger.warn("Missing X-File-Name header");
            result.put("success", false);
            result.put("message", "Missing X-File-Name header");
            return result;
        }
        
        long startTime = System.currentTimeMillis();
        
        // Create a temporary file
        Path tempFile = Files.createTempFile("direct-upload-", originalFilename);
        logger.info("Created temporary file: {}", tempFile);
        
        try (InputStream inputStream = request.getInputStream();
             FileOutputStream outputStream = new FileOutputStream(tempFile.toFile())) {
            
            // Copy the input stream to the temporary file
            byte[] buffer = new byte[8192]; // 8KB buffer
            int bytesRead;
            long totalBytes = 0;
            
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
                totalBytes += bytesRead;
            }
            
            logger.info("Copied {} bytes to temporary file", totalBytes);
            
            // Use the original filename as the fileId
            String fileId = originalFilename;
            logger.info("Using fileId: {}", fileId);
            
            boolean success = storageServiceFactory.getStorageService().storeFileStreaming(fileId, new FileInputStream(tempFile.toFile()));
            logger.info("File storage result: {}", success);
            
            // if (success) {
            //     // Store metadata in Vault
            //     Map<String, Object> metadata = new HashMap<>();
            //     metadata.put("fileId", fileId);
            //     metadata.put("originalFilename", originalFilename);
            //     metadata.put("size", totalBytes);
            //     metadata.put("timestamp", System.currentTimeMillis());
            //     metadata.put("isEncrypted", true);
                
            //     try {
            //         logger.info("Storing metadata in Vault for fileId: {}", fileId);
            //         vaultService.storeMetadata(fileId, metadata);
            //         logger.info("Successfully stored metadata for fileId: {}", fileId);
            //     } catch (Exception e) {
            //         logger.error("Failed to store metadata for fileId: {}", fileId, e);
            //         // Don't fail the upload if metadata storage fails
            //     }
            // }
            
            long totalTime = System.currentTimeMillis() - startTime;
            logger.info("Completed direct stream upload: {} bytes in {} ms", totalBytes, totalTime);
            
            result.put("success", success);
            result.put("fileId", fileId);
            result.put("originalFilename", originalFilename);
            result.put("size", totalBytes);
            result.put("timeMs", totalTime);
            result.put("message", success ? "File uploaded successfully" : "Failed to store file");
            
        } catch (Exception e) {
            logger.error("Error during direct upload: {}", originalFilename, e);
            result.put("success", false);
            result.put("message", "Error during upload: " + e.getMessage());
        } finally {
            // Clean up temporary file
            try {
                Files.deleteIfExists(tempFile);
                logger.info("Cleaned up temporary file: {}", tempFile);
            } catch (Exception e) {
                logger.warn("Failed to delete temporary file: {}", tempFile, e);
            }
        }
        
        return result;
    }

    @DeleteMapping("/api/files/{fileId}")
    @ResponseBody
    public Map<String, Object> deleteFile(@PathVariable String fileId) {
        Map<String, Object> response = new HashMap<>();
        try {
            if (fileId == null || fileId.trim().isEmpty()) {
                response.put("success", false);
                response.put("message", "Invalid file ID");
                return response;
            }

            // Delete the file directly using the fileId
            boolean success = storageServiceFactory.getStorageService().deleteFile(fileId);
            response.put("success", success);
            if (!success) {
                response.put("message", "File not found or could not be deleted");
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", e.getMessage());
        }
        return response;
    }

    @GetMapping("/api/files/download/{fileId}")
    public ResponseEntity<StreamingResponseBody> downloadFile(@PathVariable String fileId) {
        logger.info("Initiating streaming download for file ID: {}", fileId);
    
        try {
            // Get metadata
            Map<String, Object> metadata = vaultService.getMetadata(fileId);
            if (metadata == null) {
                logger.warn("Metadata not found for file ID: {}", fileId);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
            }

            // Get file stream
            InputStream fileStream = storageServiceFactory.getStorageService().retrieveFile(fileId);
            if (fileStream == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
            }

            String originalFilename = (String) metadata.get("originalFilename");
            
            // Create streaming response
            StreamingResponseBody responseBody = outputStream -> {
                try (fileStream) {
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = fileStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }
                    outputStream.flush();
                } catch (Exception e) {
                    logger.error("Error streaming file: {}", fileId, e);
                    throw new RuntimeException("Failed to stream file", e);
                }
            };

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + originalFilename + "\"")
                    .body(responseBody);
    
        } catch (Exception e) {
            logger.error("Failed to process streaming download for: {}", fileId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    @GetMapping("/api/files/view/{fileId}")
    public ResponseEntity<Resource> viewFile(@PathVariable String fileId) {
        try {
            // Get metadata
            Map<String, Object> metadata = vaultService.getMetadata(fileId);
            if (metadata == null) {
                return ResponseEntity.notFound().build();
            }

            // Get file stream
            InputStream fileStream = storageServiceFactory.getStorageService().retrieveFile(fileId);
            if (fileStream == null) {
                return ResponseEntity.notFound().build();
            }

            String originalFilename = (String) metadata.get("originalFilename");
            // Determine content type
            String contentType = determineContentType(originalFilename);
            
            // Create resource from stream
            InputStreamResource resource = new InputStreamResource(fileStream);
            
            // Set headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType(contentType));
            
            return ResponseEntity.ok()
                    .headers(headers)
                    .body(resource);
                    
        } catch (Exception e) {
            logger.error("Failed to view file: {}", fileId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    private String determineContentType(String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            logger.warn("Cannot determine content type for null or empty filename");
            return "application/octet-stream";
        }

        try {
            String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
            switch (extension) {
                case "txt":
                    return "text/plain";
                case "pdf":
                    return "application/pdf";
                case "jpg":
                case "jpeg":
                    return "image/jpeg";
                case "png":
                    return "image/png";
                case "gif":
                    return "image/gif";
                case "html":
                    return "text/html";
                case "css":
                    return "text/css";
                case "js":
                    return "application/javascript";
                case "json":
                    return "application/json";
                case "xml":
                    return "application/xml";
                default:
                    return "application/octet-stream";
            }
        } catch (Exception e) {
            logger.warn("Error determining content type for file: {}", fileName, e);
            return "application/octet-stream";
        }
    }

    @GetMapping("/api/performance")
    @ResponseBody
    public Map<String, Object> getPerformanceMetrics() {
        try {
            Map<String, Object> metrics = storageServiceFactory.getStorageService().getMetrics();
            
            // Format metrics for display
            Map<String, Object> formattedMetrics = new HashMap<>();
            
            // System metrics
            formattedMetrics.put("cpu_usage", metrics.getOrDefault("cpu_usage", "0.00"));
            formattedMetrics.put("memory_usage", metrics.getOrDefault("memory_usage", "0.00"));
            formattedMetrics.put("non_heap_memory", metrics.getOrDefault("non_heap_memory_mb", "0.00"));
            
            // Performance metrics
            formattedMetrics.put("throughput", metrics.getOrDefault("throughput_ops", "0.00"));
            formattedMetrics.put("data_read", metrics.getOrDefault("data_read_kb", "0.00"));
            formattedMetrics.put("data_written", metrics.getOrDefault("data_written_kb", "0.00"));
            formattedMetrics.put("data_processed", metrics.getOrDefault("data_processed", "0.00"));
            
            // Operation metrics
            formattedMetrics.put("total_operations", metrics.getOrDefault("total_operations", 0));
            formattedMetrics.put("average_time", metrics.getOrDefault("average_time", "0.00"));
            formattedMetrics.put("success_rate", metrics.getOrDefault("success_rate", "0.00"));
            
            // Proxy metrics
            formattedMetrics.put("proxy_latency", metrics.getOrDefault("proxy_latency", "0.00"));
            formattedMetrics.put("request_time", metrics.getOrDefault("request_time", "0.00"));
            formattedMetrics.put("response_time", metrics.getOrDefault("response_time", "0.00"));
            formattedMetrics.put("proxy_overhead", metrics.getOrDefault("proxy_overhead", "0.00"));
            
            // Encryption metrics
            formattedMetrics.put("encryption_throughput", metrics.getOrDefault("encryption_throughput", "0.00"));
            formattedMetrics.put("decryption_throughput", metrics.getOrDefault("decryption_throughput", "0.00"));
            
            return formattedMetrics;
            
        } catch (Exception e) {
            logger.error("Error getting performance metrics: {}", e.getMessage(), e);
            return new HashMap<>();
        }
    }

    @GetMapping("/management")
    public String showStorageManagement(Model model) {
        model.addAttribute("currentStorageType", proxyConfig.getStorageType());
        return "storage-management";
    }

    @PostMapping("/storage/switch")
    @ResponseBody
    public ResponseEntity<String> switchStorageType(@RequestParam String type) {
        try {
            if (!type.equalsIgnoreCase("glusterfs") && !type.equalsIgnoreCase("hdfs")) {
                return ResponseEntity.badRequest().body("Invalid storage type. Use 'glusterfs' or 'hdfs'");
            }
            
            // Update storage type in configuration
            proxyConfig.setStorageType(type);
            
            // Reinitialize storage service
            storageServiceFactory.initializeStorageService(proxyConfig.getStorageConfig());
            
            return ResponseEntity.ok("Switched to " + type + " storage");
        } catch (Exception e) {
            logger.error("Error switching storage type", e);
            return ResponseEntity.status(500).body("Error switching storage type");
        }
    }

    @GetMapping("/metrics/comparison")
    @ResponseBody
    public Map<String, Object> getStorageMetricsComparison() {
        try {
            // Get metrics from current storage service
            Map<String, Object> currentMetrics = storageServiceFactory.getStorageService().getMetrics();
            String currentStorageType = proxyConfig.getStorageType();
            
            // Convert metrics to StorageMetrics object
            StorageMetrics storageMetrics = new StorageMetrics();
            storageMetrics.setTotalSpace(Long.parseLong(currentMetrics.getOrDefault("total_space", "0").toString()));
            storageMetrics.setUsedSpace(Long.parseLong(currentMetrics.getOrDefault("used_space", "0").toString()));
            storageMetrics.setFreeSpace(Long.parseLong(currentMetrics.getOrDefault("free_space", "0").toString()));
            storageMetrics.setCpuUsage(Double.parseDouble(currentMetrics.getOrDefault("cpu_usage", "0.0").toString()));
            storageMetrics.setMemoryUsage(Double.parseDouble(currentMetrics.getOrDefault("memory_usage", "0.0").toString()));
            storageMetrics.setNetworkThroughput(Double.parseDouble(currentMetrics.getOrDefault("network_throughput", "0.0").toString()));
            storageMetrics.setDiskLatency(Double.parseDouble(currentMetrics.getOrDefault("disk_latency", "0.0").toString()));
            storageMetrics.setActiveConnections(Integer.parseInt(currentMetrics.getOrDefault("active_connections", "0").toString()));
            
            // Update comparison service
            StorageType storageType = StorageType.valueOf(currentStorageType.toUpperCase());
            metricsComparisonService.updateMetrics(storageType, storageMetrics);
            
            // Get and return comparison metrics
            Map<String, Object> comparison = new HashMap<>();
            comparison.put("current_storage_type", currentStorageType);
            comparison.put("metrics", currentMetrics);
            
            // Log the comparison
            logger.info("Storage metrics comparison for {}: {}", currentStorageType, currentMetrics);
            
            return comparison;
        } catch (Exception e) {
            logger.error("Error getting storage metrics comparison", e);
            return new HashMap<>();
        }
    }

    @PostMapping("/metrics/reset")
    @ResponseBody
    public ResponseEntity<String> resetMetrics() {
        try {
            // Reset metrics in the storage service
            storageServiceFactory.getStorageService().getMetrics().clear();
            return ResponseEntity.ok("Metrics reset successfully");
        } catch (Exception e) {
            logger.error("Error resetting metrics", e);
            return ResponseEntity.status(500).body("Error resetting metrics");
        }
    }
} 