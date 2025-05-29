package org.example.services;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.example.config.ProxyConfig;
import org.example.entities.FileInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

@Service
public class RemoteHDFSService implements StorageService {
    private static final Logger logger = LoggerFactory.getLogger(RemoteHDFSService.class);
    private static final int BUFFER_SIZE = 8192;
    private static final int MAX_RETRIES = 3;
    private static final long RETRY_DELAY_MS = 1000;
    
    private final ProxyConfig config;
    private FileSystem hdfs;
    private String basePath;
    private final HDFSService hdfsService;  // Delegate to HDFSService for encryption and other operations

    public RemoteHDFSService(MetricsServiceImpl metricsService, PerformanceMetricsService performanceMetrics) {
        this.config = ProxyConfig.getInstance();
        this.hdfsService = new HDFSService(config, metricsService, performanceMetrics);
        initializeHDFS();
        // Set the HDFS FileSystem in HDFSService
        this.hdfsService.setFileSystem(this.hdfs);
    }

    private void initializeHDFS() {
        try {
            Configuration conf = new Configuration();
            // Use the remote namenode URL from config
            conf.set("fs.defaultFS", config.getHdfsNamenodeUrl());
            conf.set("hadoop.security.authentication", "simple");
            conf.set("dfs.client.use.datanode.hostname", "true");
            
            // Increase timeout values
            conf.set("dfs.client.socket-timeout", "300000"); // 5 minutes
            conf.set("dfs.datanode.socket.write.timeout", "300000");
            conf.set("dfs.client.block.write.locateFollowingBlock.retries", "10");
            conf.set("dfs.client.block.write.retries", "10");
            conf.set("dfs.client.max.block.acquire.failures", "10");
            
            // Set HDFS user
            String hdfsUser = config.getHdfsUserName();
            if (hdfsUser != null && !hdfsUser.isEmpty()) {
                System.setProperty("HADOOP_USER_NAME", hdfsUser);
            }
            
            // Initialize HDFS connection
            hdfs = FileSystem.get(new URI(config.getHdfsNamenodeUrl()), conf);
            basePath = config.getHdfsBasePath();
            
            // Ensure base path exists
            Path basePathObj = new Path(basePath);
            if (!hdfs.exists(basePathObj)) {
                hdfs.mkdirs(basePathObj);
            }
            
            logger.info("Initialized remote HDFS connection to {} with base path {}", 
                config.getHdfsNamenodeUrl(), basePath);
        } catch (Exception e) {
            logger.error("Failed to initialize remote HDFS connection", e);
            throw new RuntimeException("Failed to initialize remote HDFS connection", e);
        }
    }

    @Override
    public void initialize(Map<String, Object> config) {
        // Initialize HDFS connection with provided config
        try {
            Configuration conf = new Configuration();
            conf.set("fs.defaultFS", (String) config.get("hdfs.namenode.url"));
            conf.set("hadoop.security.authentication", "simple");
            conf.set("dfs.client.use.datanode.hostname", "true");
            
            String hdfsUser = (String) config.get("hdfs.user.name");
            if (hdfsUser != null && !hdfsUser.isEmpty()) {
                System.setProperty("HADOOP_USER_NAME", hdfsUser);
            }
            
            hdfs = FileSystem.get(new URI((String) config.get("hdfs.namenode.url")), conf);
            
            // Get and validate base path
            this.basePath = (String) config.get("hdfs.base.path");
            if (this.basePath == null || this.basePath.isEmpty()) {
                throw new IllegalArgumentException("hdfs.base.path cannot be null or empty");
            }
            
            // Ensure base path exists
            Path basePathObj = new Path(basePath);
            if (!hdfs.exists(basePathObj)) {
                hdfs.mkdirs(basePathObj);
            }
            
            logger.info("Initialized remote HDFS connection with config: namenode={}, basePath={}", 
                config.get("hdfs.namenode.url"), basePath);
        } catch (Exception e) {
            logger.error("Failed to initialize remote HDFS connection with config", e);
            throw new RuntimeException("Failed to initialize remote HDFS connection", e);
        }
    }

    @Override
    public String storeFile(InputStream inputStream, String fileName, long fileSize, Map<String, Object> metadata) {
        return hdfsService.storeFile(inputStream, fileName, fileSize, metadata);
    }

    @Override
    public InputStream retrieveFile(String fileId) {
        return hdfsService.retrieveFile(fileId);
    }

    @Override
    public boolean deleteFile(String fileId) {
        try {
            Path hdfsPath = new Path(basePath, fileId);
            if (hdfs.exists(hdfsPath)) {
                boolean deleted = hdfs.delete(hdfsPath, false);
                if (deleted) {
                    logger.info("File deleted from remote HDFS: {}", fileId);
                    return true;
                }
            }
            return false;
        } catch (IOException e) {
            logger.error("Failed to delete file from remote HDFS: {}", fileId, e);
            throw new RuntimeException("Failed to delete file from remote HDFS: " + fileId, e);
        }
    }

    @Override
    public List<FileInfo> listFiles() {
        List<FileInfo> files = new ArrayList<>();
        try {
            logger.info("Listing files from remote HDFS path: {}", basePath);
            Path hdfsPath = new Path(basePath);
            if (!hdfs.exists(hdfsPath)) {
                logger.warn("Remote HDFS path does not exist: {}", hdfsPath);
                return Collections.emptyList();
            }
            
            org.apache.hadoop.fs.FileStatus[] statuses = hdfs.listStatus(hdfsPath);
            logger.info("Found {} files in remote HDFS", statuses.length);
            
            for (org.apache.hadoop.fs.FileStatus status : statuses) {
                String filename = status.getPath().getName();
                logger.info("Processing remote HDFS file: {}", filename);
                
                // Get metadata from Vault using the filename as the fileId
                Map<String, Object> metadata = hdfsService.getVaultService().getMetadata(filename);
                if (metadata != null) {
                    // Validate and ensure required metadata fields
                    String originalFilename = (String) metadata.get("originalFilename");
                    if (originalFilename == null) {
                        logger.warn("No originalFilename in metadata for file: {}, using filename as fallback", filename);
                        originalFilename = filename;
                    }
                    
                    long fileSize = 0;
                    Object sizeObj = metadata.get("originalSize");
                    if (sizeObj instanceof Number) {
                        fileSize = ((Number) sizeObj).longValue();
                    } else if (sizeObj != null) {
                        try {
                            fileSize = Long.parseLong(sizeObj.toString());
                        } catch (NumberFormatException e) {
                            logger.warn("Invalid size format in metadata for file: {}, using actual file size", filename);
                            fileSize = status.getLen();
                        }
                    } else {
                        logger.warn("No size in metadata for file: {}, using actual file size", filename);
                        fileSize = status.getLen();
                    }
                    
                    long timestamp = 0;
                    Object timestampObj = metadata.get("timestamp");
                    if (timestampObj instanceof Number) {
                        timestamp = ((Number) timestampObj).longValue();
                    } else if (timestampObj != null) {
                        try {
                            timestamp = Long.parseLong(timestampObj.toString());
                        } catch (NumberFormatException e) {
                            logger.warn("Invalid timestamp format in metadata for file: {}, using modification time", filename);
                            timestamp = status.getModificationTime();
                        }
                    } else {
                        logger.warn("No timestamp in metadata for file: {}, using modification time", filename);
                        timestamp = status.getModificationTime();
                    }
                    
                    logger.info("Found metadata for remote HDFS file {}: originalFilename={}, size={}, timestamp={}", 
                        filename, originalFilename, fileSize, timestamp);
                    
                    files.add(new FileInfo(
                        originalFilename,
                        fileSize,
                        Instant.ofEpochMilli(timestamp),
                        false
                    ));
                } else {
                    logger.warn("No metadata found for remote HDFS file: {}, using file attributes", filename);
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
            logger.error("Failed to list files from remote HDFS", e);
        }
        
        logger.info("Returning {} files from remote HDFS", files.size());
        return files;
    }

    @Override
    public String getFilePath(String fileId) {
        return basePath + "/" + fileId;
    }

    @Override
    public boolean storeFileStreaming(String fileId, InputStream inputStream) {
        return hdfsService.storeFileStreaming(fileId, inputStream);
    }

    @Override
    public void cleanup() {
        try {
            if (hdfs != null) {
                hdfs.close();
            }
        } catch (IOException e) {
            logger.error("Failed to cleanup remote HDFS connection", e);
        }
    }

    @Override
    public Map<String, Object> getMetrics() {
        return hdfsService.getMetrics();
    }

    @Override
    public void clearMetrics() {
        hdfsService.clearMetrics();
    }

    @Override
    public byte[] retrieveFileAsBytes(String fileId) {
        return hdfsService.retrieveFileAsBytes(fileId);
    }

    @Override
    public OutputStream createStorageOutputStream(String fileId) {
        try {
            Path hdfsPath = new Path(basePath, fileId);
            return hdfs.create(hdfsPath, true);
        } catch (IOException e) {
            logger.error("Failed to create output stream for file: {}", fileId, e);
            throw new RuntimeException("Failed to create output stream", e);
        }
    }

    // Helper method to access HDFSService's VaultService
    public VaultService getVaultService() {
        return hdfsService.getVaultService();
    }
} 