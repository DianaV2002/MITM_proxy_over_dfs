package org.example.services;

import org.example.config.ProxyConfig;
import org.example.encryption.AlgorithmSelector;
import org.example.encryption.EncryptionAlgorithm;
import org.example.encryption.AESGCMAlgorithm;
import org.example.entities.EncryptionResult;
import org.example.entities.FileInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.security.SecureRandom;

import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.Map;
import java.util.HashMap;
import java.util.Base64;
import java.util.UUID;

@Service
public class GlusterFSNFSService implements StorageService {
    private static final Logger logger = LoggerFactory.getLogger(GlusterFSNFSService.class);
    private static final String AES_KEY_NAME = "aes-encryption-key";
    private static final String CHACHA_KEY_NAME = "chacha-encryption-key";
    
    private ProxyConfig config;
    private AtomicReference<String> currentMountPoint = new AtomicReference<>();
    private String volumePath;
    private ConcurrentHashMap<String, Path> filePathCache = new ConcurrentHashMap<>();
    private EncryptionService encryptionService;
    VaultService vaultService;
    private MetricsServiceImpl metricsService;
    private PerformanceMetricsService performanceMetrics;

    public GlusterFSNFSService(MetricsServiceImpl metricsService, PerformanceMetricsService performanceMetrics) {
        this.config = ProxyConfig.getInstance();
        this.encryptionService = new EncryptionService();
        this.vaultService = new VaultService();
        this.metricsService = metricsService;
        this.performanceMetrics = performanceMetrics;
        this.volumePath = "/data/gluster/gv0";
        logger.info("Initializing GlusterFSNFSService with metrics services: metricsService={}, performanceMetrics={}", 
            metricsService != null, performanceMetrics != null);
        ensureMounted();
    }

    private void ensureMounted() {
        try {
            Path mountPath = Paths.get(volumePath);
            if (!Files.exists(mountPath)) {
                Files.createDirectories(mountPath);
            }
            
            if (!isMounted(volumePath)) {
                mountGlusterFS();
            }
            
            currentMountPoint.set(volumePath);
            logger.info("GlusterFS volume mounted at: {}", volumePath);
        } catch (IOException e) {
            logger.error("Failed to mount GlusterFS volume", e);
            throw new RuntimeException("Failed to mount GlusterFS volume", e);
        }
    }

    private boolean isMounted(String path) {
        try {
            Process process = Runtime.getRuntime().exec("mount");
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains(path)) {
                        return true;
                    }
                }
            }
        } catch (IOException e) {
            logger.warn("Failed to check mount status", e);
        }
        return false;
    }

    private void mountGlusterFS() {
        try {
            String glusterHost = config.getGlusterHost();
            String volume = config.getGlusterVolume();
            String mountCommand = String.format("sudo mount -t glusterfs %s:/%s %s", glusterHost, volume, volumePath);
            
            Process process = Runtime.getRuntime().exec(mountCommand);
            int exitCode = process.waitFor();
            
            if (exitCode != 0) {
                throw new RuntimeException("Failed to mount GlusterFS volume. Exit code: " + exitCode);
            }
            
            logger.info("Successfully mounted GlusterFS volume {} at {}", volume, volumePath);
        } catch (Exception e) {
            logger.error("Error mounting GlusterFS volume", e);
            throw new RuntimeException("Failed to mount GlusterFS volume", e);
        }
    }

    @Override
    public void initialize(Map<String, Object> config) {
        this.config = ProxyConfig.getInstance();
        this.encryptionService = new EncryptionService();
        this.vaultService = new VaultService();
        this.metricsService = metricsService;
        this.performanceMetrics = performanceMetrics;
        this.volumePath = (String) config.get("gluster.mountPoint");
        ensureMounted();
    }

    @Override
    public String storeFile(InputStream inputStream, String fileName, long fileSize, Map<String, Object> metadata) {
        long startTime = System.nanoTime();
        try {
            // Read file data
            byte[] fileData = inputStream.readAllBytes();
            long readTime = System.nanoTime() - startTime;
            
            // Record read operation
            metricsService.recordBasicIOOperation(fileData.length, 0, TimeUnit.NANOSECONDS.toMillis(readTime));
            
            // Select encryption algorithm based on file size
            String algorithm = fileSize > 1024 * 1024 ? "ChaCha20-Poly1305" : "AES-GCM";
            long encStartTime = System.nanoTime();
            
            // Encrypt file
            String fileId = UUID.randomUUID().toString();
            EncryptionResult result = encryptionService.encrypt(fileId, fileData, fileSize, false, false);
            long encTime = System.nanoTime() - encStartTime;
            
            // Record encryption metrics
            metricsService.recordEncryptionOperation(algorithm, fileSize, encTime);
            performanceMetrics.recordEncryptionOperation(algorithm, fileSize, encTime);
            
            // Store encrypted data
            long storeStartTime = System.nanoTime();
            Path filePath = Paths.get(volumePath, fileId);
            //Files.write(filePath, Base64.getDecoder().decode(result.getCiphertext()));
            Files.write(filePath, result.getCiphertext().getBytes(StandardCharsets.UTF_8));
            long storeTime = System.nanoTime() - storeStartTime;
            
            // Record write operation
            metricsService.recordBasicIOOperation(0, result.getCiphertext().length(), TimeUnit.NANOSECONDS.toMillis(storeTime));
            
            // Store metadata in Vault
            long vaultStartTime = System.nanoTime();
            Map<String, Object> fileMetadata = new HashMap<>(metadata);
            fileMetadata.put("algorithm", result.getAlgorithm());
            fileMetadata.put("originalSize", fileSize);
            fileMetadata.put("format", "binary");  // Set format to binary for all files
            vaultService.storeMetadata(fileId, fileMetadata);
            long vaultTime = System.nanoTime() - vaultStartTime;
            
            // Calculate and record total operation time
            long totalTime = System.nanoTime() - startTime;
            double proxyOverhead = ((double) (totalTime - (readTime + encTime + storeTime + vaultTime)) / totalTime) * 100;
            
            Map<String, Object> metrics = new HashMap<>();
            metrics.put("proxy_latency", TimeUnit.NANOSECONDS.toMillis(totalTime));
            metrics.put("proxy_overhead", String.format("%.2f", proxyOverhead));
            metricsService.updateMetrics(metrics);
            
            // Print session metrics after operation
            printSessionMetrics();
            
            return fileId;
        } catch (Exception e) {
            logger.error("Failed to store file: {}", fileName, e);
            throw new RuntimeException("Failed to store file", e);
        }
    }

    @Override
    public InputStream retrieveFile(String fileId) {
        logger.info("Retrieving file: {}", fileId);
        long startTime = System.nanoTime();
        metricsService.setCurrentFile(fileId);

        try {
            // Get metadata from Vault
            Map<String, Object> metadata = vaultService.getMetadata(fileId);
            if (metadata == null) {
                throw new RuntimeException("Metadata not found for file: " + fileId);
            }

            String algorithm = (String) metadata.get("algorithm");
            boolean isChunked = Boolean.TRUE.equals(metadata.get("isChunked"));
            long fileSize = ((Number) metadata.getOrDefault("size", 0L)).longValue();

            // Read encrypted data
            Path filePath = Paths.get(volumePath, fileId);
            byte[] encryptedData = Files.readAllBytes(filePath);

            // Create a PipedInputStream/PipedOutputStream pair for streaming
            PipedInputStream pis = new PipedInputStream();
            PipedOutputStream pos = new PipedOutputStream(pis);

            // Start decryption in a separate thread
            new Thread(() -> {
                try {
                    long decStart = System.nanoTime();
                    
                    // Decrypt the data
                    byte[] decryptedData = encryptionService.decrypt(fileId, encryptedData, algorithm);
                    pos.write(decryptedData);
                    
                    long decTime = System.nanoTime() - decStart;
                    
                    // Record decryption metrics
                    metricsService.recordDecryptionOperation(algorithm, fileSize, TimeUnit.NANOSECONDS.toMillis(decTime));
                    performanceMetrics.recordDecryptionOperation(algorithm, fileSize, TimeUnit.NANOSECONDS.toMillis(decTime));
                    performanceMetrics.recordBytesRead(fileSize);
                    metricsService.recordOperation(org.example.model.StorageType.LOCAL, true, fileSize);

                    // Calculate and record total operation time
                    long totalTime = System.nanoTime() - startTime;
                    double proxyOverhead = ((double)(totalTime - decTime) / totalTime) * 100;

                    // Store performance metrics
                    Map<String, Object> metrics = new HashMap<>();
                    metrics.put("proxy_latency", TimeUnit.NANOSECONDS.toMillis(totalTime));
                    metrics.put("request_time", 0); // No request delay in streaming read
                    metrics.put("response_time", TimeUnit.NANOSECONDS.toMillis(decTime));
                    metrics.put("proxy_overhead", proxyOverhead);
                    metrics.put("decryption_throughput", (fileSize / (1024.0 * 1024.0)) / (decTime / 1000.0));
                    metrics.put("data_processed", fileSize / 1024.0);
                    metrics.put("total_operations", 1);
                    metrics.put("average_time", TimeUnit.NANOSECONDS.toMillis(totalTime));
                    metrics.put("success_rate", 100.0);
                    metricsService.updateMetrics(metrics);

                    pos.close();
                } catch (Exception e) {
                    logger.error("Error during decryption: {}", fileId, e);
                    try {
                        pos.close();
                    } catch (IOException ex) {
                        logger.error("Error closing output stream: {}", fileId, ex);
                    }
                }
            }).start();

            displayOperationMetrics("retrieveFile", fileId, startTime);
            
            // Print session metrics after operation
            printSessionMetrics();
            
            return pis;
        } catch (Exception e) {
            logger.error("Failed to retrieve file: {}", fileId, e);
            throw new RuntimeException("Failed to retrieve file: " + fileId, e);
        } finally {
            metricsService.clearCurrentFile();
        }
    }
    

    @Override
    public boolean deleteFile(String fileId) {
        try {
            Path filePath = Paths.get(volumePath, fileId);
            if (Files.exists(filePath)) {
                Files.delete(filePath);
                logger.info("File deleted: {}", fileId);
            }
            return true;
        } catch (IOException e) {
            logger.error("Failed to delete file: {}", fileId, e);
            throw new RuntimeException("Failed to delete file: " + fileId, e);
        }
    }

    @Override
    public byte[] retrieveFileAsBytes(String fileId) {
        try {
            // First check if this is a document or image file
            Map<String, Object> metadata = vaultService.getMetadata(fileId);
            if (metadata != null) {
                String originalFilename = (String) metadata.get("originalFilename");
                final boolean isImageOrDocument = originalFilename != null && 
                    (originalFilename.toLowerCase().endsWith(".jpg") || 
                     originalFilename.toLowerCase().endsWith(".jpeg") || 
                     originalFilename.toLowerCase().endsWith(".png") || 
                     originalFilename.toLowerCase().endsWith(".pdf") || 
                     originalFilename.toLowerCase().endsWith(".doc") || 
                     originalFilename.toLowerCase().endsWith(".docx") ||
                     originalFilename.toLowerCase().endsWith(".xls") || 
                     originalFilename.toLowerCase().endsWith(".xlsx"));
                
                if (isImageOrDocument) {
                    // For image/document files, try to decrypt but catch errors
                    Path filePath = Paths.get(volumePath, fileId);
                    if (Files.exists(filePath)) {
                        try {
                            // Check file signature first
                            byte[] fileStart = new byte[8];
                            try (InputStream signatureCheck = Files.newInputStream(filePath)) {
                                int bytesRead = signatureCheck.read(fileStart);
                                if (bytesRead >= 4) {
                                    // Check for common file signatures
                                    if ((bytesRead >= 8 && 
                                        fileStart[0] == (byte)0x89 && fileStart[1] == (byte)0x50 && 
                                        fileStart[2] == (byte)0x4E && fileStart[3] == (byte)0x47 &&
                                        fileStart[4] == (byte)0x0D && fileStart[5] == (byte)0x0A &&
                                        fileStart[6] == (byte)0x1A && fileStart[7] == (byte)0x0A) || // PNG
                                        (fileStart[0] == (byte)0xFF && fileStart[1] == (byte)0xD8 && 
                                        fileStart[2] == (byte)0xFF) || // JPEG
                                        (fileStart[0] == (byte)0x25 && fileStart[1] == (byte)0x50 && 
                                        fileStart[2] == (byte)0x44 && fileStart[3] == (byte)0x46)) { // PDF
                                        
                                        logger.info("File {} appears to be a raw binary file, serving directly", fileId);
                                        return Files.readAllBytes(filePath);
                                    }
                                }
                            }
                            
                            // Try decryption first
                            try (InputStream in = retrieveFile(fileId)) {
                                return in.readAllBytes();
                            } catch (Exception e) {
                                // If decryption fails, return raw file content
                                logger.warn("Decryption failed for image/document file. Serving raw content for: {}", fileId);
                                return Files.readAllBytes(filePath);
                            }
                        } catch (Exception e) {
                            logger.error("Failed to process image/document file: {}", fileId, e);
                            // Fall back to raw content as last resort
                            return Files.readAllBytes(filePath);
                        }
                    }
                }
            }
            
            // For all other files, use the standard method
            try (InputStream in = retrieveFile(fileId)) {
                return in.readAllBytes();
            } catch (IOException e) {
                logger.error("Failed to retrieve file as bytes: {}", fileId, e);
                throw new RuntimeException("Failed to retrieve file as bytes: " + fileId, e);
            }
        } catch (Exception e) {
            logger.error("Failed to retrieve file as bytes: {}", fileId, e);
            throw new RuntimeException("Failed to retrieve file as bytes: " + fileId, e);
        }
    }

    @Override
    public List<FileInfo> listFiles() {
        List<FileInfo> files = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(Paths.get(volumePath))) {
            for (Path path : stream) {
                if (Files.isRegularFile(path)) {
                    FileInfo fileInfo = new FileInfo(
                        path.getFileName().toString(),
                        Files.size(path),
                        Files.getLastModifiedTime(path).toInstant(),
                        false
                    );
                    files.add(fileInfo);
                }
            }
        } catch (IOException e) {
            logger.error("Failed to list files", e);
        }
        return files;
    }

    @Override
    public String getFilePath(String fileId) {
        return Paths.get(volumePath, fileId).toString();
    }

    @Override
    public boolean storeFileStreaming(String fileId, InputStream inputStream) {
        logger.info("Streaming file upload: {}", fileId);
        long startTime = System.nanoTime();
        metricsService.setCurrentFile(fileId);

        try {
            // Use the original fileId without modification
            Path storagePath = Paths.get(volumePath, fileId);
            Files.createDirectories(storagePath.getParent());

            // Estimate file size
            long fileSize = inputStream.available();
            boolean isLargeFile = fileSize > 1024 * 1024;

            // Select algorithm
            AlgorithmSelector.FileProperties props = new AlgorithmSelector.FileProperties(fileSize, false, 0, false);
            EncryptionAlgorithm algorithm = AlgorithmSelector.selectAlgorithm(props);
            logger.info("Using {} algorithm for file: {} ({} bytes)", algorithm.getName(), fileId, fileSize);

            // Start timing encryption
            long encStartTime = System.nanoTime();

            // Encrypt the file and get the Vault ciphertext string
            String ciphertext = encryptionService.encryptChunkedStreamToString(fileId, inputStream, fileSize, false, false, algorithm);
            Files.writeString(storagePath, ciphertext, StandardCharsets.UTF_8);

            long encTime = System.nanoTime() - encStartTime;

            // Performance tracking
            double encryptionThroughput = (fileSize / (1024.0 * 1024.0)) / (encTime / 1000.0);
            
            // Record metrics
            metricsService.recordEncryptionOperation(algorithm.getName(), fileSize, TimeUnit.NANOSECONDS.toMillis(encTime));
            performanceMetrics.recordEncryptionOperation(algorithm.getName(), fileSize, TimeUnit.NANOSECONDS.toMillis(encTime));
            performanceMetrics.recordBytesWritten(fileSize);
            metricsService.recordOperation(org.example.model.StorageType.LOCAL, true, fileSize);

            long totalTime = System.nanoTime() - startTime;
            double proxyOverhead = ((double) (totalTime - encTime) / totalTime) * 100;

            // Record proxy latency
            performanceMetrics.recordProxyLatency("storeFileStreaming", TimeUnit.NANOSECONDS.toMillis(encTime), TimeUnit.NANOSECONDS.toMillis(totalTime));

            // Store performance metrics
            Map<String, Object> metrics = new HashMap<>();
            metrics.put("proxy_latency", TimeUnit.NANOSECONDS.toMillis(totalTime));
            metrics.put("request_time", TimeUnit.NANOSECONDS.toMillis(encTime));
            metrics.put("response_time", 0); // No response delay in streaming write
            metrics.put("proxy_overhead", proxyOverhead);
            metrics.put("encryption_throughput", encryptionThroughput);
            metrics.put("data_processed", fileSize / 1024.0);
            metrics.put("total_operations", 1);
            metrics.put("average_time", TimeUnit.NANOSECONDS.toMillis(totalTime));
            metrics.put("success_rate", 100.0);
            metricsService.updateMetrics(metrics);

            // Save metadata to Vault
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("fileId", fileId);
            metadata.put("originalFilename", fileId);
            metadata.put("storagePath", storagePath.toString());
            metadata.put("size", fileSize);
            metadata.put("timestamp", System.currentTimeMillis());
            metadata.put("isEncrypted", true);
            metadata.put("algorithm", algorithm.getName());
            metadata.put("keyName", algorithm instanceof AESGCMAlgorithm ? AES_KEY_NAME : CHACHA_KEY_NAME);
            metadata.put("isChunked", isLargeFile);
            vaultService.storeMetadata(fileId, metadata);

            logger.info("Stored metadata for file: {}", fileId);

            displayOperationMetrics("storeFileStreaming", fileId, startTime);

            return true;
        } catch (Exception e) {
            metricsService.handleEncryptionFailure(fileId, e);
            logger.error("Failed to store file: {}", fileId, e);
            throw new RuntimeException("Failed to store file: " + fileId, e);
        } finally {
            metricsService.clearCurrentFile();
        }
    }

    @Override
    public void cleanup() {
        try {
            Path dirPath = Paths.get(volumePath);
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(dirPath)) {
                for (Path path : stream) {
                    if (Files.isRegularFile(path)) {
                        Files.delete(path);
                    }
                }
            }
        } catch (IOException e) {
            logger.error("Failed to cleanup files", e);
            throw new RuntimeException("Failed to cleanup files", e);
        }
    }

    @Override
    public OutputStream createStorageOutputStream(String fileId) {
        try {
            Path filePath = Paths.get(volumePath, fileId);
            Files.createDirectories(filePath.getParent());
            return Files.newOutputStream(filePath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        } catch (IOException e) {
            logger.error("Failed to create output stream: {}", fileId, e);
            throw new RuntimeException("Failed to create output stream: " + fileId, e);
        }
    }

    @Override
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        // Get current metrics from metrics service
        Map<String, Object> currentMetrics = metricsService.getPerformanceMetrics();
        if (currentMetrics != null) {
            metrics.putAll(currentMetrics);
        }
        
        // Get detailed metrics from performance metrics service
        Map<String, Object> detailedMetrics = performanceMetrics.getDetailedPerformanceMetrics();
        if (detailedMetrics != null) {
            metrics.putAll(detailedMetrics);
        }
        
        // Calculate total operations and success rate
        long totalOps = ((Number) metrics.getOrDefault("total_operations", 0L)).longValue();
        long totalErrors = ((Number) metrics.getOrDefault("total_errors", 0L)).longValue();
        double successRate = totalOps > 0 ? ((totalOps - totalErrors) * 100.0) / totalOps : 0.0;
        metrics.put("total_operations", totalOps);
        metrics.put("success_rate", String.format("%.2f", successRate));
        
        // Calculate throughput
        double avgTime = ((Number) metrics.getOrDefault("average_time", 0.0)).doubleValue();
        double throughput = avgTime > 0 ? (totalOps * 1000.0) / avgTime : 0.0;
        metrics.put("throughput", String.format("%.2f", throughput));
        
        // Calculate total data processed
        long bytesRead = ((Number) metrics.getOrDefault("data_read", 0L)).longValue();
        long bytesWritten = ((Number) metrics.getOrDefault("data_written", 0L)).longValue();
        long totalDataProcessed = bytesRead + bytesWritten;
        metrics.put("data_processed", String.format("%.2f", totalDataProcessed / 1024.0));
        
        // Calculate proxy latency metrics
        double proxyLatency = ((Number) metrics.getOrDefault("proxy_latency", 0.0)).doubleValue();
        double requestTime = ((Number) metrics.getOrDefault("request_time", 0.0)).doubleValue();
        double responseTime = ((Number) metrics.getOrDefault("response_time", 0.0)).doubleValue();
        double totalProxyTime = requestTime + responseTime;
        double proxyOverhead = totalProxyTime > 0 ? (proxyLatency / totalProxyTime) * 100 : 0.0;
        
        metrics.put("proxy_latency", String.format("%.2f", proxyLatency));
        metrics.put("request_time", String.format("%.2f", requestTime));
        metrics.put("response_time", String.format("%.2f", responseTime));
        metrics.put("proxy_overhead", String.format("%.2f", proxyOverhead));
        
        // Calculate encryption/decryption throughput
        double encryptionThroughput = ((Number) metrics.getOrDefault("encryption_throughput", 0.0)).doubleValue();
        double decryptionThroughput = ((Number) metrics.getOrDefault("decryption_throughput", 0.0)).doubleValue();
        metrics.put("encryption_throughput", String.format("%.2f", encryptionThroughput));
        metrics.put("decryption_throughput", String.format("%.2f", decryptionThroughput));
        
        // Add system metrics
        metrics.put("cpu_usage", String.format("%.2f", ((Number) metrics.getOrDefault("cpu_usage", 0.0)).doubleValue()));
        metrics.put("memory_usage", String.format("%.2f", ((Number) metrics.getOrDefault("memory_usage", 0.0)).doubleValue()));
        metrics.put("non_heap_memory", String.format("%.2f", ((Number) metrics.getOrDefault("non_heap_memory_mb", 0.0)).doubleValue()));
        
        return metrics;
    }
    
    private double getCPUUsage() {
        try {
            com.sun.management.OperatingSystemMXBean osBean = 
                (com.sun.management.OperatingSystemMXBean) java.lang.management.ManagementFactory.getOperatingSystemMXBean();
            return osBean.getSystemCpuLoad() * 100;
        } catch (Exception e) {
            return 0.0;
        }
    }

    private double getMemoryUsage() {
        try {
            java.lang.management.MemoryMXBean memoryBean = 
                java.lang.management.ManagementFactory.getMemoryMXBean();
            return (memoryBean.getHeapMemoryUsage().getUsed() * 100.0) / 
                   memoryBean.getHeapMemoryUsage().getMax();
        } catch (Exception e) {
            return 0.0;
        }
    }

    private double getNonHeapMemoryUsage() {
        try {
            java.lang.management.MemoryMXBean memoryBean = 
                java.lang.management.ManagementFactory.getMemoryMXBean();
            return memoryBean.getNonHeapMemoryUsage().getUsed() / (1024.0 * 1024.0);
        } catch (Exception e) {
            return 0.0;
        }
    }

    @Override
    public void clearMetrics() {
        metricsService.clearMetrics();
    }

    private String generateRandomPadding() {
        SecureRandom random = new SecureRandom();
        byte[] padding = new byte[16];
        random.nextBytes(padding);
        return Base64.getEncoder().encodeToString(padding);
    }

    private void displayOperationMetrics(String operation, String fileName, long startTime) {
        long totalTime = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
        
        // Get metrics from both services
        Map<String, Object> basicMetrics = metricsService.getPerformanceMetrics();
        Map<String, Object> detailedMetrics = performanceMetrics.getDetailedPerformanceMetrics();
        
        logger.info("=== Operation Metrics for: {} - File: {} ===", operation, fileName);
        logger.info("Total operation time: {} ms", totalTime);
        
        // Basic Metrics
        Map<String, Object> operations = (Map<String, Object>) basicMetrics.get("operations");
        if (operations != null) {
            Map<String, Object> basicIO = (Map<String, Object>) operations.get("basicIO");
            Map<String, Object> encryption = (Map<String, Object>) operations.get("encryption");
            Map<String, Object> decryption = (Map<String, Object>) operations.get("decryption");
            
            if (basicIO != null) {
                logger.info("Basic I/O - Total Operations: {}, Avg Time: {} ms", 
                    basicIO.getOrDefault("totalOperations", 0),
                    basicIO.getOrDefault("averageTime", 0));
            }
            
            if (encryption != null) {
                logger.info("Encryption - Total: {}, Avg Time: {} ms, Overhead: {}%", 
                    encryption.getOrDefault("totalOperations", 0),
                    encryption.getOrDefault("averageTime", 0),
                    encryption.getOrDefault("overhead", 0));
            }
            
            if (decryption != null) {
                logger.info("Decryption - Total: {}, Avg Time: {} ms, Overhead: {}%", 
                    decryption.getOrDefault("totalOperations", 0),
                    decryption.getOrDefault("averageTime", 0),
                    decryption.getOrDefault("overhead", 0));
            }
        }
        
        // Detailed Performance Metrics
        Map<String, Object> encPerf = (Map<String, Object>) detailedMetrics.get("encryption_performance");
        Map<String, Object> decPerf = (Map<String, Object>) detailedMetrics.get("decryption_performance");
        Map<String, Object> latency = (Map<String, Object>) detailedMetrics.get("operation_latency");
        
        if (encPerf != null && !encPerf.isEmpty()) {
            logger.info("=== Encryption Performance ===");
            encPerf.forEach((algorithm, stats) -> {
                if (stats instanceof Map) {
                    Map<String, Object> algStats = (Map<String, Object>) stats;
                    double avgTime = 0.0;
                    int opCount = 0;
                    try {
                        Object avgTimeObj = algStats.get("average_time_ms");
                        Object opCountObj = algStats.get("operations_count");
                        avgTime = avgTimeObj instanceof Number ? ((Number) avgTimeObj).doubleValue() : 
                                 avgTimeObj instanceof String ? Double.parseDouble((String) avgTimeObj) : 0.0;
                        opCount = opCountObj instanceof Number ? ((Number) opCountObj).intValue() : 
                                 opCountObj instanceof String ? Integer.parseInt((String) opCountObj) : 0;
                    } catch (Exception e) {
                        logger.warn("Error parsing metrics for algorithm {}: {}", algorithm, e.getMessage());
                    }
                    
                    double throughput = opCount > 0 ? ((double) getLongValue(basicMetrics, "totalBytesRead", 0L) / (1024.0 * 1024.0)) / (avgTime / 1000.0) : 0.0;
                    logger.info("{} - Avg Throughput: {:.2f} MB/s, Operations: {}", 
                        algorithm, throughput, opCount);
                }
            });
        }
        
        if (decPerf != null && !decPerf.isEmpty()) {
            logger.info("=== Decryption Performance ===");
            decPerf.forEach((algorithm, stats) -> {
                if (stats instanceof Map) {
                    Map<String, Object> algStats = (Map<String, Object>) stats;
                    double avgTime = 0.0;
                    int opCount = 0;
                    try {
                        Object avgTimeObj = algStats.get("average_time_ms");
                        Object opCountObj = algStats.get("operations_count");
                        avgTime = avgTimeObj instanceof Number ? ((Number) avgTimeObj).doubleValue() : 
                                 avgTimeObj instanceof String ? Double.parseDouble((String) avgTimeObj) : 0.0;
                        opCount = opCountObj instanceof Number ? ((Number) opCountObj).intValue() : 
                                 opCountObj instanceof String ? Integer.parseInt((String) opCountObj) : 0;
                    } catch (Exception e) {
                        logger.warn("Error parsing metrics for algorithm {}: {}", algorithm, e.getMessage());
                    }
                    
                    double throughput = opCount > 0 ? ((double) getLongValue(basicMetrics, "totalBytesRead", 0L) / (1024.0 * 1024.0)) / (avgTime / 1000.0) : 0.0;
                    logger.info("{} - Avg Throughput: {:.2f} MB/s, Operations: {}", 
                        algorithm, throughput, opCount);
                }
            });
        }
        
        if (latency != null && !latency.isEmpty()) {
            logger.info("=== Operation Latency ===");
            latency.forEach((op, overhead) -> {
                double overheadValue = 0.0;
                try {
                    overheadValue = overhead instanceof Number ? ((Number) overhead).doubleValue() : 
                                   overhead instanceof String ? Double.parseDouble((String) overhead) : 0.0;
                } catch (Exception e) {
                    logger.warn("Error parsing overhead for operation {}: {}", op, e.getMessage());
                }
                logger.info("{} - Overhead: {:.2f}%", op, overheadValue);
            });
        }
        
        logger.info("=====================================");
    }
    
    private long getLongValue(Map<String, Object> map, String key, long defaultValue) {
        if (map == null || key == null) return defaultValue;
        Object value = map.get(key);
        if (value == null) return defaultValue;
        try {
            if (value instanceof Number) {
                return ((Number) value).longValue();
            } else if (value instanceof String) {
                return Long.parseLong((String) value);
            }
            return defaultValue;
        } catch (Exception e) {
            return defaultValue;
        }
    }

    // Retrieval: always read ciphertext as string
    public String retrieveCiphertextAsString(String fileId) {
        try {
            Path filePath = Paths.get(volumePath, fileId);
            if (!Files.exists(filePath)) {
                throw new RuntimeException("File not found: " + fileId);
            }
            return Files.readString(filePath, StandardCharsets.UTF_8);
        } catch (IOException e) {
            logger.error("Failed to read ciphertext as string for file: {}", fileId, e);
            throw new RuntimeException("Failed to read ciphertext as string for file: " + fileId, e);
        }
    }

    public VaultService getVaultService() {
        return this.vaultService;
    }

    private void printSessionMetrics() {
        // Get detailed metrics from performance metrics service
        Map<String, Object> detailedMetrics = performanceMetrics.getDetailedPerformanceMetrics();
        
        // Initialize counters
        long totalEncBytes = 0;
        long totalEncTime = 0;
        long totalDecBytes = 0;
        long totalDecTime = 0;
        int encOps = 0;
        int decOps = 0;
        
        // Get encryption performance metrics
        if (detailedMetrics != null) {
            Map<String, Object> encPerf = (Map<String, Object>) detailedMetrics.get("encryption_performance");
            if (encPerf != null) {
                for (Map.Entry<String, Object> entry : encPerf.entrySet()) {
                    if (entry.getValue() instanceof Map) {
                        Map<String, Object> stats = (Map<String, Object>) entry.getValue();
                        long bytesProcessed = getLongValue(stats, "bytes_processed", 0L);
                        long timeMs = getLongValue(stats, "total_time_ms", 0L);
                        int ops = getIntValue(stats, "operations_count", 0);
                        
                        if (timeMs > 0 && bytesProcessed > 0) {
                            totalEncBytes += bytesProcessed;
                            totalEncTime += timeMs;
                            encOps += ops;
                        }
                    }
                }
            }
            
            // Get decryption performance metrics
            Map<String, Object> decPerf = (Map<String, Object>) detailedMetrics.get("decryption_performance");
            if (decPerf != null) {
                for (Map.Entry<String, Object> entry : decPerf.entrySet()) {
                    if (entry.getValue() instanceof Map) {
                        Map<String, Object> stats = (Map<String, Object>) entry.getValue();
                        long bytesProcessed = getLongValue(stats, "bytes_processed", 0L);
                        long timeMs = getLongValue(stats, "total_time_ms", 0L);
                        int ops = getIntValue(stats, "operations_count", 0);
                        
                        if (timeMs > 0 && bytesProcessed > 0) {
                            totalDecBytes += bytesProcessed;
                            totalDecTime += timeMs;
                            decOps += ops;
                        }
                    }
                }
            }
        }
        
        // Calculate throughput and time per MB
        double encThroughput = totalEncTime > 0 ? (totalEncBytes / (1024.0 * 1024.0)) / (totalEncTime / 1000.0) : 0.0;
        double decThroughput = totalDecTime > 0 ? (totalDecBytes / (1024.0 * 1024.0)) / (totalDecTime / 1000.0) : 0.0;
        
        double encTimePerMB = encThroughput > 0 ? 1000.0 / encThroughput : 0.0;
        double decTimePerMB = decThroughput > 0 ? 1000.0 / decThroughput : 0.0;
        
        // Get total operations and success rate
        int totalOps = encOps + decOps;
        Map<String, Object> metrics = getMetrics();
        long totalErrors = ((Number) metrics.getOrDefault("total_errors", 0L)).longValue();
        double successRate = totalOps > 0 ? ((totalOps - totalErrors) * 100.0) / totalOps : 0.0;
        
        // Print metrics
        logger.info("=== Session Encryption/Decryption Metrics ===");
        logger.info("Avg. Encryption Time: {} ms/MB", String.format("%.2f", encTimePerMB));
        logger.info("Avg. Decryption Time: {} ms/MB", String.format("%.2f", decTimePerMB));
        logger.info("Avg. Encryption Speed: {} MB/s", String.format("%.2f", encThroughput));
        logger.info("Avg. Decryption Speed: {} MB/s", String.format("%.2f", decThroughput));
        logger.info("Total Operations: {} (Enc: {}, Dec: {})", totalOps, encOps, decOps);
        logger.info("Success Rate: {}%", String.format("%.2f", successRate));
        logger.info("Total Data Processed: {} MB", String.format("%.2f", (totalEncBytes + totalDecBytes) / (1024.0 * 1024.0)));
        logger.info("=========================================");
    }
    
    private int getIntValue(Map<String, Object> map, String key, int defaultValue) {
        if (map == null || key == null) return defaultValue;
        Object value = map.get(key);
        if (value == null) return defaultValue;
        try {
            if (value instanceof Number) {
                return ((Number) value).intValue();
            } else if (value instanceof String) {
                return Integer.parseInt((String) value);
            }
            return defaultValue;
        } catch (Exception e) {
            return defaultValue;
        }
    }
}
