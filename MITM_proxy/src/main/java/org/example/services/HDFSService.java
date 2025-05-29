package org.example.services;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.example.config.ProxyConfig;
import org.example.encryption.AlgorithmSelector;
import org.example.encryption.EncryptionAlgorithm;
import org.example.encryption.AESGCMAlgorithm;
import org.example.encryption.Chacha20Poly1305Algorithm;
import org.example.entities.EncryptionResult;
import org.example.entities.FileInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.nio.charset.StandardCharsets;
import java.util.Base64;


@Service
public class HDFSService implements StorageService {
    private static final Logger logger = LoggerFactory.getLogger(HDFSService.class);
    private static final int BUFFER_SIZE = 8192;
    private static final int MAX_RETRIES = 5;
    private static final long RETRY_DELAY_MS = 2000;
    private static final int HDFS_TIMEOUT_MS = 300000;  // Increased to 5 minutes timeout
    private static final int CHUNK_SIZE = 1024 * 1024;  // 1MB chunks
    private static final String KEY_PATH = "secret/data/encryption";
    private static final String AES_KEY_NAME = "aes-encryption-key";
    private static final String CHACHA_KEY_NAME = "chacha-encryption-key";

    private final ProxyConfig proxyConfig;
    private FileSystem hdfs;
    private String basePath;
    private EncryptionService encryptionService;
    private VaultService vaultService;
    private MetricsServiceImpl metricsService;
    private PerformanceMetricsService performanceMetrics;

    public HDFSService(ProxyConfig config, MetricsServiceImpl metricsService, PerformanceMetricsService performanceMetrics) {
        this.proxyConfig = config;
        this.metricsService = metricsService;
        this.performanceMetrics = performanceMetrics;
        this.encryptionService = new EncryptionService();
        this.vaultService = new VaultService();
        this.basePath = proxyConfig.getHdfsBasePath();
        
        // Initialize HDFS with proper configuration
        initializeHDFS();
        
        logger.info("Initializing HDFSService with metrics services: metricsService={}, performanceMetrics={}, basePath={}", 
            metricsService != null, performanceMetrics != null, basePath);
    }

    private void initializeHDFS() {
        try {
            Configuration conf = new Configuration();
            conf.set("fs.defaultFS", proxyConfig.getHdfsNamenodeUrl());
            conf.set("hadoop.security.authentication", "simple");
            conf.set("dfs.client.use.datanode.hostname", "true");
            
            // Set timeouts and retry settings
            conf.set("dfs.client.socket-timeout", String.valueOf(HDFS_TIMEOUT_MS));
            conf.set("dfs.datanode.socket.write.timeout", String.valueOf(HDFS_TIMEOUT_MS));
            conf.set("dfs.client.block.write.locateFollowingBlock.retries", "10");
            conf.set("dfs.client.block.write.retries", "10");
            conf.set("dfs.client.max.block.acquire.failures", "10");
            
            // Network settings
            conf.set("dfs.client.socket-timeout", String.valueOf(HDFS_TIMEOUT_MS));
            conf.set("ipc.client.connect.timeout", String.valueOf(HDFS_TIMEOUT_MS));
            conf.set("ipc.client.connect.max.retries", "10");
            conf.set("ipc.client.connect.retry.interval", "1000");
            
            // Set HDFS user
            String hdfsUser = proxyConfig.getHdfsUserName();
            if (hdfsUser != null && !hdfsUser.isEmpty()) {
                System.setProperty("HADOOP_USER_NAME", hdfsUser);
            }
            
            // Initialize HDFS connection with retry logic
            int connectionRetries = 0;
            while (connectionRetries < MAX_RETRIES) {
                try {
                    hdfs = FileSystem.get(new URI(proxyConfig.getHdfsNamenodeUrl()), conf);
                    
                    // Test the connection
                    if (hdfs.exists(new Path("/"))) {
                        logger.info("Successfully connected to HDFS");
                        break;
                    }
                } catch (Exception e) {
                    connectionRetries++;
                    if (connectionRetries == MAX_RETRIES) {
                        logger.error("Failed to initialize HDFS connection after {} retries", MAX_RETRIES, e);
                        throw new RuntimeException("Failed to initialize HDFS connection", e);
                    }
                    logger.warn("Failed to connect to HDFS (attempt {}/{}), retrying...", connectionRetries, MAX_RETRIES);
                    try {
                        TimeUnit.MILLISECONDS.sleep(RETRY_DELAY_MS);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new RuntimeException("Interrupted while retrying HDFS connection", ie);
                    }
                }
            }
            
            // Ensure base path exists
            Path basePathObj = new Path(basePath);
            if (!hdfs.exists(basePathObj)) {
                hdfs.mkdirs(basePathObj);
            }
            
            logger.info("Initialized HDFS connection to {} with base path {}", 
                proxyConfig.getHdfsNamenodeUrl(), basePath);
        } catch (Exception e) {
            logger.error("Failed to initialize HDFS connection", e);
            throw new RuntimeException("Failed to initialize HDFS connection", e);
        }
    }

    public void setFileSystem(FileSystem hdfs) {
        this.hdfs = hdfs;
        logger.info("Set HDFS FileSystem in HDFSService");
    }

    @Override
    public void initialize(Map<String, Object> config) {
        // No initialization needed for HDFS service
    }


    @Override
    public String storeFile(InputStream inputStream, String fileName, long fileSize, Map<String, Object> metadata) {
        long startTime = System.nanoTime();
        String fileId = UUID.randomUUID().toString();
        
        try {
            // Read file data
            byte[] fileData = inputStream.readAllBytes();
            long readTime = System.nanoTime() - startTime;
            
            // Record read operation
            if (metricsService != null) {
                metricsService.recordBasicIOOperation(fileData.length, 0, TimeUnit.NANOSECONDS.toMillis(readTime));
            }
            
            // Select encryption algorithm based on file size
            String algorithm = fileSize > 1024 * 1024 ? "ChaCha20-Poly1305" : "AES-GCM";
            long encStartTime = System.nanoTime();
            
            // Encrypt file
            EncryptionResult result = encryptionService.encrypt(fileId, fileData, fileSize, false, false);
            long encTime = System.nanoTime() - encStartTime;
            
            // Record encryption metrics
            if (metricsService != null && performanceMetrics != null) {
                metricsService.recordEncryptionOperation(algorithm, fileSize, encTime);
                performanceMetrics.recordEncryptionOperation(
                    algorithm,
                    fileSize,
                    encTime
                );
            }
            
            // Write encrypted data to HDFS
            Path hdfsPath = new Path(basePath, fileId);
            int retries = 0;
            while (retries < MAX_RETRIES) {
                try (FSDataOutputStream out = hdfs.create(hdfsPath, true)) {
                    // Write the ciphertext as raw bytes
                    byte[] encryptedData = Base64.getDecoder().decode(result.getCiphertext());
                    out.write(encryptedData);
                    break;
                } catch (Exception e) {
                    retries++;
                    if (retries == MAX_RETRIES) {
                        logger.error("Failed to store file after {} retries: {}", MAX_RETRIES, fileId, e);
                        throw new RuntimeException("Failed to store encrypted file", e);
                    }
                    try {
                        TimeUnit.MILLISECONDS.sleep(RETRY_DELAY_MS);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new RuntimeException("Interrupted while retrying", ie);
                    }
                }
            }
            
            // Store metadata in Vault
            long vaultStartTime = System.nanoTime();
            Map<String, Object> fileMetadata = createFileMetadata(fileId, fileName, fileSize, fileData);
            fileMetadata.put("algorithm", algorithm);
            fileMetadata.put("keyName", algorithm.equals("AES-GCM") ? AES_KEY_NAME : CHACHA_KEY_NAME);
            fileMetadata.put("fileId", fileId);
            
            logger.info("Storing metadata for file {}: {}", fileId, fileMetadata);
            vaultService.storeMetadata(fileId, fileMetadata);
            long vaultTime = System.nanoTime() - vaultStartTime;
            
            // Calculate and record total operation time
            long totalTime = System.nanoTime() - startTime;
            double proxyOverhead = ((double) (totalTime - (readTime + encTime + vaultTime)) / totalTime) * 100;
            
            if (metricsService != null) {
                Map<String, Object> metrics = new HashMap<>();
                metrics.put("proxy_latency", TimeUnit.NANOSECONDS.toMillis(totalTime));
                metrics.put("proxy_overhead", String.format("%.2f", proxyOverhead));
                metricsService.updateMetrics(metrics);
            }
            
            logger.info("Successfully stored encrypted file: {}", fileId);
            return fileId;
        } catch (Exception e) {
            logger.error("Failed to store encrypted file: {}", fileName, e);
            if (metricsService != null) {
                metricsService.handleEncryptionFailure(fileId, e);
            }
            throw new RuntimeException("Failed to store encrypted file", e);
        }
    }

    @Override
    public InputStream retrieveFile(String fileId) {
        long startTime = System.nanoTime();
        try {
            // Get metadata from Vault
            long vaultStart = System.nanoTime();
            Map<String, Object> metadata = vaultService.getMetadata(fileId);
            if (metadata == null) {
                throw new RuntimeException("Failed to retrieve metadata for file: " + fileId);
            }
            long vaultTime = System.nanoTime() - vaultStart;
            
            Path hdfsPath = new Path(basePath, fileId);
            if (!hdfs.exists(hdfsPath)) {
                throw new FileNotFoundException("File not found: " + fileId);
            }

            // Create piped streams for async decryption with larger buffer
            PipedOutputStream pos = new PipedOutputStream();
            PipedInputStream pis = new PipedInputStream(pos, 32768);  // Increased buffer size to 32KB

            // Start async decryption
            Thread decryptThread = new Thread(() -> {
                try (FSDataInputStream in = hdfs.open(hdfsPath)) {
                    // Read the encrypted data as raw bytes
                    byte[] encryptedData = in.readAllBytes();
                    
                    // Get the algorithm from metadata
                    String algorithm = (String) metadata.get("algorithm");
                    if (algorithm == null) {
                        throw new RuntimeException("No algorithm specified in metadata for file: " + fileId);
                    }
                    
                    // Decrypt the data
                    byte[] decryptedData = encryptionService.decrypt(fileId, encryptedData, algorithm);
                    
                    // Write the decrypted data to the output stream
                    pos.write(decryptedData);
                    pos.flush();
                } catch (Exception e) {
                    logger.error("Error during decryption: {}", e.getMessage(), e);
                    try {
                        pos.close();
                    } catch (IOException ie) {
                        logger.error("Error closing output stream: {}", ie.getMessage(), ie);
                    }
                } finally {
                    try {
                        pos.close();
                    } catch (IOException e) {
                        logger.error("Error closing output stream: {}", e.getMessage(), e);
                    }
                }
            });
            decryptThread.start();

            // Return an InputStream that reads from the decrypted data
            return new InputStream() {
                private boolean closed = false;
                
                @Override
                public int read() throws IOException {
                    if (closed) {
                        throw new IOException("Stream closed");
                    }
                    return pis.read();
                }
                
                @Override
                public int read(byte[] b, int off, int len) throws IOException {
                    if (closed) {
                        throw new IOException("Stream closed");
                    }
                    return pis.read(b, off, len);
                }
                
                @Override
                public void close() throws IOException {
                    if (!closed) {
                        closed = true;
                        pis.close();
                        // Interrupt the decrypt thread if it's still running
                        if (decryptThread.isAlive()) {
                            decryptThread.interrupt();
                        }
                    }
                }
            };
        } catch (Exception e) {
            logger.error("Failed to retrieve file: {}", fileId, e);
            throw new RuntimeException("Failed to retrieve file: " + fileId, e);
        }
    }

    @Override
    public boolean deleteFile(String fileId) {
        try {
            if (fileId == null || fileId.trim().isEmpty()) {
                logger.error("Cannot delete file: fileId is null or empty");
                return false;
            }

            Path hdfsPath = new Path(basePath, fileId);
            if (hdfs.exists(hdfsPath)) {
                boolean deleted = hdfs.delete(hdfsPath, false);
                if (deleted) {
                    logger.info("File deleted: {}", fileId);
                    return true;
                } else {
                    logger.error("Failed to delete file: {} - delete operation returned false", fileId);
                    return false;
                }
            } else {
                logger.warn("File not found for deletion: {}", fileId);
                return false;
            }
        } catch (IOException e) {
            logger.error("Failed to delete file: {}", fileId, e);
            throw new RuntimeException("Failed to delete file: " + fileId, e);
        }
    }

    @Override
    public List<FileInfo> listFiles() {
        List<FileInfo> files = new ArrayList<>();
        try {
            logger.info("Listing files from HDFS path: {}", basePath);
            Path hdfsPath = new Path(basePath);
            if (!hdfs.exists(hdfsPath)) {
                logger.warn("HDFS path does not exist: {}", hdfsPath);
                return Collections.emptyList();
            }
            
            org.apache.hadoop.fs.FileStatus[] statuses = hdfs.listStatus(hdfsPath);
            logger.info("Found {} files in HDFS", statuses.length);
            
            for (org.apache.hadoop.fs.FileStatus status : statuses) {
                String filename = status.getPath().getName();
                logger.info("Processing HDFS file: {}", filename);
                
                // Get metadata from Vault using the filename as the fileId
                Map<String, Object> metadata = vaultService.getMetadata(filename);
                if (metadata != null) {
                    String originalFilename = (String) metadata.get("originalFilename");
                    long fileSize = ((Number) metadata.getOrDefault("size", 0L)).longValue();
                    long timestamp = ((Number) metadata.getOrDefault("timestamp", 0L)).longValue();
                    
                    logger.info("Found metadata for HDFS file {}: originalFilename={}, size={}, timestamp={}", 
                        filename, originalFilename, fileSize, timestamp);
                    
                    files.add(new FileInfo(
                        originalFilename,
                        fileSize,
                        Instant.ofEpochMilli(timestamp),
                        false
                    ));
                } else {
                    logger.warn("No metadata found for HDFS file: {}", filename);
                    // If metadata not found, use the filename directly
                    files.add(new FileInfo(
                        filename,
                        status.getLen(),
                        Instant.ofEpochMilli(status.getModificationTime()),
                        false
                    ));
                }
            }
        } catch (IOException e) {
            logger.error("Failed to list files from HDFS", e);
        }
        
        logger.info("Returning {} files from HDFS", files.size());
        return files;
    }

    @Override
    public String getFilePath(String fileId) {
        return basePath + "/" + fileId;
    }

    // @Override
    // public boolean storeFileStreaming(String fileId, InputStream inputStream) {
    //     logger.info("Starting file upload with fileId: {}", fileId);
    //     long startTime = System.nanoTime();
    //     metricsService.setCurrentFile(fileId);

    //     try {
    //         // Verify HDFS connection is still valid
    //         if (hdfs == null || !hdfs.exists(new Path("/"))) {
    //             logger.warn("HDFS connection lost, attempting to reconnect");
    //             initializeHDFS();
    //         }

    //         String originalFilename = fileId;
    //         Path hdfsPath = new Path(basePath, originalFilename);
            
    //         // Check if HDFS is available
    //         if (!hdfs.exists(hdfsPath.getParent())) {
    //             logger.warn("HDFS parent directory does not exist, attempting to create: {}", hdfsPath.getParent());
    //             if (!hdfs.mkdirs(hdfsPath.getParent())) {
    //                 logger.error("Failed to create HDFS directory: {}", hdfsPath.getParent());
    //                 return false;
    //             }
    //         }

    //         // Estimate file size
    //         long fileSize = inputStream.available();
    //         logger.info("File size: {} bytes", fileSize);
    //         boolean isLargeFile = fileSize > 1024 * 1024;

    //         // Select algorithm
    //         AlgorithmSelector.FileProperties props = new AlgorithmSelector.FileProperties(fileSize, false, 0, false);
    //         EncryptionAlgorithm algorithm = AlgorithmSelector.selectAlgorithm(props);
    //         logger.info("Using {} algorithm for file: {} ({} bytes)", algorithm.getName(), originalFilename, fileSize);

    //         // Start timing encryption
    //         long encStartTime = System.nanoTime();

    //         // Create a temporary file to store the encrypted data
    //         // java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("encrypted-", ".tmp");
    //         // logger.info("Created temporary file for encryption: {}", tempFile);

    //         try (OutputStream outputStream = Files.newOutputStream(basePath, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
    //             encryptionService.encryptChunkedStream(fileId, inputStream, outputStream, fileSize, false, false);
    //             // tempOutputStream.flush();
    //         }

    //         // Read the encrypted data from the temporary file
    //         // byte[] encryptedData = java.nio.file.Files.readAllBytes(tempFile);
    //         // logger.info("Read {} bytes of encrypted data from temporary file", encryptedData.length);

    //         // Write encrypted data to HDFS with progress tracking
    //         boolean writeSuccess = false;
    //         int retries = 0;
    //         long lastProgressLogTime = System.currentTimeMillis();
    //         int lastProgressPercent = 0;

    //         while (retries < MAX_RETRIES && !writeSuccess) {
    //             try (FSDataOutputStream outputStream = hdfs.create(hdfsPath, true)) {
    //                 // Write data in chunks with progress tracking
    //                 int offset = 0;
    //                 int totalBytes = encryptedData.length;
                    
    //                 while (offset < totalBytes) {
    //                     int chunkSize = Math.min(CHUNK_SIZE, totalBytes - offset);
    //                     outputStream.write(encryptedData, offset, chunkSize);
    //                     offset += chunkSize;

    //                     // Log progress every 5% or every 5 seconds
    //                     int progressPercent = (int) ((offset * 100.0) / totalBytes);
    //                     long currentTime = System.currentTimeMillis();
    //                     if (progressPercent >= lastProgressPercent + 5 || 
    //                         currentTime - lastProgressLogTime >= 5000) {
    //                         logger.info("HDFS write progress: {}% ({} bytes)", progressPercent, offset);
    //                         lastProgressPercent = progressPercent;
    //                         lastProgressLogTime = currentTime;
    //                     }
    //                 }
                    
    //                 // Flush and sync to ensure data is written
    //                 outputStream.hflush();
    //                 outputStream.hsync();
                    
    //                 // Verify the file exists and has the correct size
    //                 if (hdfs.exists(hdfsPath)) {
    //                     long writtenSize = hdfs.getFileStatus(hdfsPath).getLen();
    //                     if (writtenSize == totalBytes) {
    //                         writeSuccess = true;
    //                         logger.info("Successfully wrote encrypted data to HDFS: {} ({} bytes)", hdfsPath, writtenSize);
    //                     } else {
    //                         logger.warn("File size mismatch: expected {} bytes, got {} bytes", totalBytes, writtenSize);
    //                     }
    //                 }
    //             } catch (Exception e) {
    //                 logger.error("Failed to write to HDFS (attempt {}/{}): {}", 
    //                     retries + 1, MAX_RETRIES, e.getMessage());
    //                 retries++;
    //                 if (retries < MAX_RETRIES) {
    //                     try {
    //                         // Exponential backoff for retries
    //                         long backoffTime = RETRY_DELAY_MS * (1L << (retries - 1));
    //                         logger.info("Retrying in {} ms...", backoffTime);
    //                         Thread.sleep(backoffTime);
    //                     } catch (InterruptedException ie) {
    //                         Thread.currentThread().interrupt();
    //                         throw new RuntimeException("Interrupted while retrying HDFS write", ie);
    //                     }
    //                 }
    //             }
    //         }

    //         // Clean up temporary file
    //         try {
    //             Files.deleteIfExists(tempFile);
    //             logger.info("Cleaned up temporary file: {}", tempFile);
    //         } catch (IOException e) {
    //             logger.warn("Failed to delete temporary file: {}", tempFile, e);
    //         }

    //         if (!writeSuccess) {
    //             logger.error("Failed to write to HDFS after {} retries", MAX_RETRIES);
    //             return false;
    //         }

    //         // Store metadata in Vault
    //         Map<String, Object> metadata = new HashMap<>();
    //         metadata.put("fileId", fileId);
    //         metadata.put("originalFilename", originalFilename);
    //         metadata.put("originalSize", fileSize);
    //         metadata.put("encryptedSize", encryptedData.length);
    //         metadata.put("timestamp", System.currentTimeMillis());
    //         metadata.put("isEncrypted", true);
    //         metadata.put("algorithm", algorithm.getName());
    //         metadata.put("keyName", algorithm instanceof AESGCMAlgorithm ? AES_KEY_NAME : CHACHA_KEY_NAME);
    //         metadata.put("isChunked", isLargeFile);
    //         metadata.put("hdfsPath", hdfsPath.toString());
            
    //         try {
    //             logger.info("Storing metadata in Vault for fileId: {}", fileId);
    //             vaultService.storeMetadata(fileId, metadata);
    //             logger.info("Successfully stored metadata in Vault for fileId: {}", fileId);
    //         } catch (Exception e) {
    //             logger.error("Failed to store metadata in Vault: {}", fileId, e);
    //             return false;
    //         }

    //         // Calculate and record metrics
    //         long encTime = System.nanoTime() - encStartTime;
    //         double encryptionThroughput = (fileSize / (1024.0 * 1024.0)) / (encTime / 1000.0);
    //         metricsService.recordEncryptionOperation(algorithm.getName(), fileSize, TimeUnit.NANOSECONDS.toMillis(encTime));
    //         performanceMetrics.recordEncryptionOperation(algorithm.getName(), fileSize, TimeUnit.NANOSECONDS.toMillis(encTime));
    //         performanceMetrics.recordBytesWritten(fileSize);

    //         long totalTime = System.nanoTime() - startTime;
    //         double proxyOverhead = ((double) (totalTime - encTime) / totalTime) * 100;

    //         // Store performance metrics
    //         Map<String, Object> metrics = new HashMap<>();
    //         metrics.put("proxy_latency", TimeUnit.NANOSECONDS.toMillis(totalTime));
    //         metrics.put("request_time", TimeUnit.NANOSECONDS.toMillis(encTime));
    //         metrics.put("response_time", 0);
    //         metrics.put("proxy_overhead", proxyOverhead);
    //         metrics.put("encryption_throughput", encryptionThroughput);
    //         metrics.put("total_operations", 1);
    //         metrics.put("average_time", TimeUnit.NANOSECONDS.toMillis(totalTime));
    //         metrics.put("success_rate", 100.0);
    //         metrics.put("data_processed", fileSize / 1024.0);
    //         metricsService.updateMetrics(metrics);

    //         return true;
    //     } catch (Exception e) {
    //         metricsService.handleEncryptionFailure(fileId, e);
    //         logger.error("Failed to store file: {}", fileId, e);
    //         return false;
    //     } finally {
    //         metricsService.clearCurrentFile();
    //     }
    // }

    
    @Override
    public boolean storeFileStreaming(String fileId, InputStream inputStream) {
        logger.info("Streaming file upload: {}", fileId);
        long startTime = System.nanoTime();
        metricsService.setCurrentFile(fileId);

        try {
            // Use the original fileId without modification
            Path storagePath = new Path(basePath, fileId);
            //Files.createDirectories(storagePath);
            hdfs.mkdirs(storagePath.getParent());

            // Estimate file size (you can improve this by passing the content length from HTTP layer if possible)
            long fileSize = inputStream.available();
            boolean isLargeFile = fileSize > 1024 * 1024;

            // Select algorithm
            AlgorithmSelector.FileProperties props = new AlgorithmSelector.FileProperties(fileSize, false, 0, false);
            EncryptionAlgorithm algorithm = AlgorithmSelector.selectAlgorithm(props);
            logger.info("Using {} algorithm for file: {} ({} bytes)", algorithm.getName(), fileId, fileSize);

            // Start timing encryption
            long encStartTime = System.nanoTime();

            // Perform stream encryption directly to file
            try (OutputStream outputStream = hdfs.create(storagePath, true))
             {
                encryptionService.encryptChunkedStream(fileId, inputStream, outputStream, fileSize, false, false);
            }

            long encTime = System.nanoTime() - encStartTime;

            // Performance tracking
            double encryptionThroughput = (fileSize / (1024.0 * 1024.0)) / (encTime / 1000.0);
            metricsService.recordEncryptionOperation(algorithm.getName(), fileSize, TimeUnit.NANOSECONDS.toMillis(encTime));
            performanceMetrics.recordEncryptionOperation(algorithm.getName(), fileSize, TimeUnit.NANOSECONDS.toMillis(encTime));
            performanceMetrics.recordBytesWritten(fileSize);

            long totalTime = System.nanoTime() - startTime;
            double proxyOverhead = ((double) (totalTime - encTime) / totalTime) * 100;

            // Proxy latency
            performanceMetrics.recordProxyLatency("storeFileStreaming", TimeUnit.NANOSECONDS.toMillis(encTime), TimeUnit.NANOSECONDS.toMillis(totalTime));

            // Store performance metrics
            Map<String, Object> metrics = new HashMap<>();
            metrics.put("proxy_latency", TimeUnit.NANOSECONDS.toMillis(totalTime));
            metrics.put("request_time", TimeUnit.NANOSECONDS.toMillis(encTime));
            metrics.put("response_time", 0); // No response delay in streaming write
            metrics.put("proxy_overhead", proxyOverhead);
            metrics.put("encryption_throughput", encryptionThroughput);
            metrics.put("total_operations", 1);
            metrics.put("average_time", TimeUnit.NANOSECONDS.toMillis(totalTime));
            metrics.put("success_rate", 100.0);
            metrics.put("data_processed", fileSize / 1024.0);
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

            // Show metrics for this operation
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
            if (hdfs != null) {
                hdfs.close();
            }
        } catch (Exception e) {
            logger.error("Failed to cleanup HDFS", e);
        }
    }

    @Override
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("total_operations", 0);
        metrics.put("successful_operations", 0);
        metrics.put("failed_operations", 0);
        metrics.put("total_bytes_transferred", 0);
        metrics.put("average_operation_time_ms", 0);
        return metrics;
    }

    @Override
    public void clearMetrics() {
        // No-op for now
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
    

    @Override
    public OutputStream createStorageOutputStream(String fileId) {
        Path hdfsPath = new Path(basePath, fileId);
        try {
            return hdfs.create(hdfsPath, true);
        } catch (IOException e) {
            logger.error("Failed to create output stream for file: {}", fileId, e);
            throw new RuntimeException("Failed to create output stream", e);
        }
    }

    @Override
    public byte[] retrieveFileAsBytes(String fileId) {
        try (InputStream in = retrieveFile(fileId)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            return out.toByteArray();
        } catch (IOException e) {
            logger.error("Failed to retrieve file as bytes: {}", fileId, e);
            throw new RuntimeException("Failed to retrieve file as bytes", e);
        }
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

    public VaultService getVaultService() {
        return vaultService;
    }

    public static boolean isBinaryContent(byte[] content) {
                if (content == null || content.length == 0) return false;
            
                // Check for PNG signature (first 8 bytes)
                if (content.length >= 8) {
                    byte[] pngSignature = new byte[]{(byte)0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
                    boolean isPng = true;
                    for (int i = 0; i < 8; i++) {
                        if (content[i] != pngSignature[i]) {
                            isPng = false;
                            break;
                        }
                    }
                    if (isPng) return true;
                }
                
                // Check for other binary indicators
                int nonPrintable = 0;
                for (int i = 0; i < Math.min(content.length, 1000); i++) {
                    byte b = content[i];
                    if (b < 32 && b != 9 && b != 10 && b != 13) { // Non-printable ASCII
                        nonPrintable++;
                    }
                }
                
                // If more than 10% of the first 1000 bytes are non-printable, consider it binary
                return nonPrintable > 100;
            }


    private Map<String, Object> createFileMetadata(String fileId, String originalFilename, long fileSize, byte[] content) {
        Map<String, Object> fileMetadata = new HashMap<>();
        fileMetadata.put("fileId", fileId);
        fileMetadata.put("originalFilename", originalFilename);
        fileMetadata.put("originalSize", fileSize);
        fileMetadata.put("timestamp", System.currentTimeMillis());
        
        // Determine format based on content type
        boolean isBinary = isBinaryContent(content);
        fileMetadata.put("format", isBinary ? "binary" : "text");
        
        return fileMetadata;
    }
} 