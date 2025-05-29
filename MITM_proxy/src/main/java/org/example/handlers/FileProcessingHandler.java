package org.example.handlers;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.*;
import io.netty.util.CharsetUtil;
import org.example.services.StorageServiceFactory;
import org.example.services.EncryptionService;
import org.example.encryption.AlgorithmSelector;
import org.example.encryption.EncryptionAlgorithm;
import org.example.services.VaultService;
import org.example.services.MetricsServiceImpl;
import org.example.model.StorageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.io.InputStream;
import java.util.concurrent.ConcurrentHashMap;
import java.nio.file.StandardOpenOption;
import java.io.IOException;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Base64;

public class FileProcessingHandler extends SimpleChannelInboundHandler<Object> {
    private static final Logger logger = LoggerFactory.getLogger(FileProcessingHandler.class);
    private final StorageServiceFactory storageServiceFactory;
    private final EncryptionService encryptionService;
    private final VaultService vaultService;
    private final MetricsServiceImpl metricsService;

    // Upload state tracking
    private static class UploadState {
        String fileName;
        Path tempFile;
        boolean isSensitive;
        boolean isHighValue;
        long accessCount;
        long fileSize;
    }
    
    private final ConcurrentHashMap<ChannelHandlerContext, UploadState> uploadStates = new ConcurrentHashMap<>();

    private static final int MIN_BUFFER_SIZE = 1024 * 1024; // 1MB minimum
    private static final int MAX_BUFFER_SIZE = 16 * 1024 * 1024; // 16MB maximum
    private static final int DEFAULT_BUFFER_SIZE = 4 * 1024 * 1024; // 4MB default

    private int calculateBufferSize(long fileSize) {
        // For files under 1MB, use minimum buffer size
        if (fileSize < MIN_BUFFER_SIZE) {
            return MIN_BUFFER_SIZE;
        }
        
        // For files over 1GB, use maximum buffer size
        if (fileSize > 1024 * 1024 * 1024) {
            return MAX_BUFFER_SIZE;
        }
        
        // For files between 1MB and 1GB, scale buffer size logarithmically
        double scale = Math.log10(fileSize / (1024.0 * 1024.0)) / Math.log10(1024.0);
        int bufferSize = (int) (MIN_BUFFER_SIZE * Math.pow(2, scale));
        
        // Round to nearest power of 2
        bufferSize = Integer.highestOneBit(bufferSize);
        
        // Ensure buffer size is within bounds
        return Math.min(Math.max(bufferSize, MIN_BUFFER_SIZE), MAX_BUFFER_SIZE);
    }

    public FileProcessingHandler(StorageServiceFactory storageServiceFactory, MetricsServiceImpl metricsService) {
        this.storageServiceFactory = storageServiceFactory;
        this.encryptionService = new EncryptionService();
        this.vaultService = new VaultService();
        this.metricsService = metricsService;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof HttpRequest) {
            HttpRequest request = (HttpRequest) msg;
            
            if (request.method() == HttpMethod.POST) {
                // Handle large file uploads gracefully
                String uri = request.uri();
                if (uri.contains("/upload-large")) {
                    // Initialize a direct upload state
                    UploadState state = new UploadState();
                    state.fileName = request.headers().get("X-File-Name");
                    if (state.fileName == null) {
                        sendError(ctx, HttpResponseStatus.BAD_REQUEST, "Missing file name");
                        return;
                    }
                    
                    state.isSensitive = request.headers().contains("X-File-Sensitive");
                    state.isHighValue = request.headers().contains("X-File-High-Value");
                    
                    // Create a temporary file for the upload
                    state.tempFile = Files.createTempFile("direct-upload-", state.fileName);
                    logger.info("Starting direct upload for file: {}", state.fileName);
                    
                    // Store the state
                    uploadStates.put(ctx, state);
                    return;
                }
                
                // Initialize regular upload state
                UploadState state = new UploadState();
                state.fileName = request.headers().get("X-File-Name");
                if (state.fileName == null) {
                    sendError(ctx, HttpResponseStatus.BAD_REQUEST, "Missing file name");
                    return;
                }
                
                state.isSensitive = request.headers().contains("X-File-Sensitive");
                state.isHighValue = request.headers().contains("X-File-High-Value");
                
                try {
                    String rawCount = request.headers().get("X-File-Access-Count");
                    if (rawCount != null) state.accessCount = Long.parseLong(rawCount);
                } catch (NumberFormatException ignored) {
                    logger.warn("Invalid access count header, defaulting to 0");
                }
                
                // Create a temporary file for the upload
                state.tempFile = Files.createTempFile("upload-", state.fileName);
                logger.info("Starting upload for file: {}", state.fileName);
                
                // Store the state
                uploadStates.put(ctx, state);
            } else if (request.method() == HttpMethod.GET) {
                handleFileDownload(request, ctx);
            } else {
                sendError(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED, "Method not allowed");
            }
        }
        
        if (msg instanceof HttpContent) {
            UploadState state = uploadStates.get(ctx);
            if (state == null) {
                return; // No active upload for this context
            }
            
            // Stream content directly to the temporary file
            HttpContent content = (HttpContent) msg;
            ByteBuf buf = content.content();
            
            if (buf.isReadable()) {
                try {
                    // Create a properly sized chunk and append directly to file
                    byte[] bytes = new byte[buf.readableBytes()];
                    buf.readBytes(bytes);
                    
                    // Append to the temporary file
                    Files.write(state.tempFile, bytes, 
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                    
                    // Update file size
                    state.fileSize += bytes.length;
                    
                    // Release the buffer immediately
                    buf.release();
                } catch (Exception e) {
                    logger.error("Error writing chunk to file", e);
                    sendError(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR, "Error writing file: " + e.getMessage());
                    // Clean up resources
                    uploadStates.remove(ctx);
                    Files.deleteIfExists(state.tempFile);
                    return;
                }
            }
            
            // Check if this is the last chunk
            if (msg instanceof LastHttpContent) {
                // Complete the upload process
                try {
                    boolean isLargeUpload = state.fileName != null && state.fileName.startsWith("direct-upload-");
                    completeFileUpload(ctx, state);
                } catch (Exception e) {
                    logger.error("Failed to complete file upload", e);
                    sendError(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR, "Failed to process upload: " + e.getMessage());
                } finally {
                    // Clean up resources
                    uploadStates.remove(ctx);
                    try {
                        Files.deleteIfExists(state.tempFile);
                    } catch (Exception e) {
                        logger.warn("Could not delete temporary file", e);
                    }
                }
            }
        }
    }

    private void completeFileUpload(ChannelHandlerContext ctx, UploadState state) {
        try {
            // Track performance metrics
            long startTime = System.nanoTime();

            AlgorithmSelector.FileProperties props = new AlgorithmSelector.FileProperties(
                state.fileSize, state.isSensitive, state.accessCount, state.isHighValue
            );
            EncryptionAlgorithm selectedAlgorithm = AlgorithmSelector.selectAlgorithm(props);
            logger.info("Selected encryption algorithm: {} for file: {} ({} bytes)", 
                selectedAlgorithm.getName(), state.fileName, state.fileSize);
            
            // Record algorithm selection decision
            Map<String, Object> algorithmMetrics = new HashMap<>();
            algorithmMetrics.put("fileSize", state.fileSize);
            algorithmMetrics.put("isSensitive", state.isSensitive);
            algorithmMetrics.put("isHighValue", state.isHighValue);
            algorithmMetrics.put("accessCount", state.accessCount);
            algorithmMetrics.put("selectedAlgorithm", selectedAlgorithm.getName());
            algorithmMetrics.put("selectionScore", calculateAlgorithmSelectionScore(state.fileSize, state.isSensitive, state.isHighValue));
            metricsService.updateMetrics(algorithmMetrics);
            
            // Stream file through encryption directly to storage
            String fileId = UUID.randomUUID().toString();
            String storageFileName = fileId + ".enc";
            
            // Track encryption time
            long encryptionStartTime = System.nanoTime();
            
            try (InputStream inputStream = Files.newInputStream(state.tempFile)) {
                storageServiceFactory.getStorageService().storeFileStreaming(fileId, inputStream);
            }
            
            long encryptionTime = System.nanoTime() - encryptionStartTime;
            metricsService.recordEncryptionOperation(selectedAlgorithm.getName(), state.fileSize, TimeUnit.NANOSECONDS.toMillis(encryptionTime));
            
            // Build a minimal metadata object
            Map<String, Object> metrics = new HashMap<>();
            metrics.put("filename", state.fileName);
            metrics.put("originalSize", state.fileSize);
            metrics.put("encryptedSize", state.fileSize);
            metrics.put("compressionRatio", String.format("%.2f%%", 
                (1.0 - (double)state.fileSize / state.fileSize) * 100));
            metrics.put("encryptionStatus", "success");
            metrics.put("algorithm", selectedAlgorithm.getName());
            metrics.put("encryptionTime", TimeUnit.NANOSECONDS.toMillis(encryptionTime));
            metrics.put("throughputMBps", String.format("%.2f", 
                (double)state.fileSize / (1024 * 1024) / (TimeUnit.NANOSECONDS.toMillis(encryptionTime) / 1000.0)));
            
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("fileId", fileId);
            metadata.put("algorithm", selectedAlgorithm.getName());
            metadata.put("timestamp", System.currentTimeMillis());
            metadata.put("originalFilename", state.fileName);
            metadata.put("storageFilename", storageFileName);
            metadata.put("size", state.fileSize);
            metadata.put("metrics", metrics);
            metadata.put("chunked", true);
            metadata.put("format", "binary");  // Set format to binary for all files
            
            // Store metadata in Vault
            vaultService.storeMetadata(fileId, metadata);
            
            // Generate visualization
            Map<String, Object> visualization = generateEncryptionVisualization(metrics);
            metadata.put("visualization", visualization);
            
            // Send success response with metrics
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("fileId", fileId);
            response.put("fileName", state.fileName);
            response.put("size", state.fileSize);
            response.put("metrics", metrics);
            response.put("visualization", visualization);
            
            // Record total operation time
            long totalTime = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
            metricsService.recordOperation(StorageType.GLUSTERFS, true, state.fileSize);
            
            sendResponse(ctx, HttpResponseStatus.OK, new ObjectMapper().writeValueAsString(response));
            
        } catch (Exception e) {
            logger.error("Failed to process file upload", e);
            sendError(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR, "Failed to process file upload: " + e.getMessage());
        } finally {
            // Clean up the temporary file
            try {
                Files.deleteIfExists(state.tempFile);
            } catch (IOException e) {
                logger.warn("Failed to delete temporary file: {}", state.tempFile, e);
            }
        }
    }
    
    private double calculateAlgorithmSelectionScore(long fileSize, boolean isSensitive, boolean isHighValue) {
        double score = 0.0;
        
        // Size factor (50% weight)
        if (fileSize > 1024 * 1024) { // > 1MB
            score += 0.5 * 0.8; // ChaCha20 preferred for large files
        } else {
            score += 0.5 * 0.9; // AES-GCM preferred for small files
        }
        
        // Sensitivity factor (30% weight)
        if (isSensitive) {
            score += 0.3 * 1.0; // AES-GCM preferred for sensitive data
        } else {
            score += 0.3 * 0.5;
        }
        
        // Value factor (20% weight)
        if (isHighValue) {
            score += 0.2 * 1.0; // AES-GCM preferred for high-value data
        } else {
            score += 0.2 * 0.5;
        }
        
        return score;
    }
    
    private Map<String, Object> generateEncryptionVisualization(Map<String, Object> metrics) {
        Map<String, Object> visualization = new HashMap<>();
        
        // Process flow visualization
        List<Map<String, Object>> steps = new ArrayList<>();
        
        // Step 1: File Upload
        Map<String, Object> uploadStep = new HashMap<>();
        uploadStep.put("step", 1);
        uploadStep.put("name", "File Upload");
        uploadStep.put("status", "completed");
        uploadStep.put("details", String.format("Original size: %d bytes", (Long)metrics.get("originalSize")));
        steps.add(uploadStep);
        
        // Step 2: Encryption
        Map<String, Object> encStep = new HashMap<>();
        encStep.put("step", 2);
        encStep.put("name", "Encryption");
        encStep.put("status", "completed");
        encStep.put("details", String.format("Algorithm: %s, Encrypted size: %d bytes", 
            metrics.get("algorithm"), (Long)metrics.get("encryptedSize")));
        steps.add(encStep);
        
        // Step 3: Storage
        Map<String, Object> storageStep = new HashMap<>();
        storageStep.put("step", 3);
        storageStep.put("name", "Secure Storage");
        storageStep.put("status", "completed");
        storageStep.put("details", "File stored with metadata in Vault");
        steps.add(storageStep);
        
        visualization.put("steps", steps);
        
        // Performance metrics
        Map<String, Object> performance = new HashMap<>();
        performance.put("compressionRatio", metrics.get("compressionRatio"));
        performance.put("originalSize", metrics.get("originalSize"));
        performance.put("finalSize", metrics.get("encryptedSize"));
        performance.put("encryptionTime", metrics.get("encryptionTime"));
        performance.put("throughputMBps", metrics.get("throughputMBps"));
        visualization.put("performance", performance);
        
        // Security status
        Map<String, Object> security = new HashMap<>();
        security.put("algorithm", metrics.get("algorithm"));
        security.put("encryptionStatus", metrics.get("encryptionStatus"));
        security.put("chunked", true);
        security.put("vaultCaching", true);
        visualization.put("security", security);
        
        return visualization;
    }

    private void handleFileDownload(HttpRequest request, ChannelHandlerContext ctx) {
        try {
            String fileId = request.headers().get("X-File-Id");
            if (fileId == null) {
                sendError(ctx, HttpResponseStatus.BAD_REQUEST, "Missing file ID");
                return;
            }

            // Get metadata from Vault (uses cache if available)
            Map<String, Object> metadata = vaultService.getMetadata(fileId);
            if (metadata == null) {
                logger.warn("Metadata not found in Vault for file ID: {}", fileId);
                sendError(ctx, HttpResponseStatus.NOT_FOUND, "File not found");
                return;
            }

            String storageFileName = (String) metadata.get("storageFilename");
            if (storageFileName == null) {
                logger.error("Invalid file metadata - missing storageFilename for file ID: {}", fileId);
                sendError(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR, "Invalid file metadata");
                return;
            }

            String originalFilename = (String) metadata.get("originalFilename");
            long fileSize = ((Number) metadata.get("size")).longValue();
            boolean isChunked = metadata.containsKey("chunked") && (boolean) metadata.get("chunked");
            String format = (String) metadata.getOrDefault("format", "binary"); // Default to binary
            boolean isBinary = !"text".equals(format); // Consider everything non-text as binary

            // Check if this is likely a document or image file
            boolean isImageOrDocument = false;
            if (originalFilename != null && 
                (originalFilename.toLowerCase().endsWith(".jpg") || 
                 originalFilename.toLowerCase().endsWith(".jpeg") || 
                 originalFilename.toLowerCase().endsWith(".png") || 
                 originalFilename.toLowerCase().endsWith(".pdf") || 
                 originalFilename.toLowerCase().endsWith(".doc") || 
                 originalFilename.toLowerCase().endsWith(".docx") ||
                 originalFilename.toLowerCase().endsWith(".xls") || 
                 originalFilename.toLowerCase().endsWith(".xlsx"))) {
                isImageOrDocument = true;
            }

            logger.info("Processing file download: {} ({} bytes, format: {}, chunked: {}, isImageOrDocument: {})", 
                originalFilename, fileSize, format, isChunked, isImageOrDocument);

            // Start HTTP response
            DefaultHttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/octet-stream");
            response.headers().set(HttpHeaderNames.TRANSFER_ENCODING, HttpHeaderValues.CHUNKED);
            response.headers().set(HttpHeaderNames.CONTENT_DISPOSITION, 
                "attachment; filename=\"" + originalFilename + "\"");
            
            ctx.write(response);
            
            // Retrieve the file
            byte[] encryptedContent = storageServiceFactory.getStorageService().retrieveFileAsBytes(storageFileName);
            if (encryptedContent == null) {
                sendError(ctx, HttpResponseStatus.NOT_FOUND, "File not found in storage");
                return;
            }

            logger.info("Retrieved encrypted content: {} bytes", encryptedContent.length);
            
            // Validate retrieved content
            if (encryptedContent.length == 0) {
                logger.error("Retrieved empty content for file: {}", fileId);
                sendError(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR, "Retrieved empty file content");
                return;
            }

            // Check for signs of corruption or non-encrypted data
            if (encryptedContent.length < 20 || encryptedContent.length < fileSize / 20) {
                logger.warn("Retrieved content appears to be corrupted - size mismatch. Expected ~{} bytes, got {} bytes", 
                           fileSize, encryptedContent.length);
            }
            
            // Check for common file signatures that would indicate raw files
            boolean isLikelyRawFile = false;
            
            // Check file signatures
            if (encryptedContent.length >= 8) {
                // PNG signature - full 8-byte check
                if (encryptedContent[0] == (byte)0x89 && encryptedContent[1] == (byte)0x50 && 
                    encryptedContent[2] == (byte)0x4E && encryptedContent[3] == (byte)0x47 &&
                    encryptedContent[4] == (byte)0x0D && encryptedContent[5] == (byte)0x0A &&
                    encryptedContent[6] == (byte)0x1A && encryptedContent[7] == (byte)0x0A) {
                    logger.warn("Content for file {} appears to be a raw PNG file (not encrypted)", fileId);
                    isLikelyRawFile = true;
                }
            }
            
            if (encryptedContent.length >= 3) {
                // JPEG signature
                if (encryptedContent[0] == (byte)0xFF && encryptedContent[1] == (byte)0xD8 && 
                     encryptedContent[2] == (byte)0xFF) {
                    logger.warn("Content for file {} appears to be a raw JPEG file (not encrypted)", fileId);
                    isLikelyRawFile = true;
                }
            }
            
            if (encryptedContent.length >= 4) {
                // PDF signature
                if (encryptedContent[0] == (byte)0x25 && encryptedContent[1] == (byte)0x50 && 
                     encryptedContent[2] == (byte)0x44 && encryptedContent[3] == (byte)0x46) {
                    logger.warn("Content for file {} appears to be a raw PDF file (not encrypted)", fileId);
                    isLikelyRawFile = true;
                }
            }
            
            byte[] decryptedContent;
            
            // If it looks like a raw file or is an image/document, try to decrypt but fall back to serving raw
            if (isLikelyRawFile) {
                logger.info("Serving content directly as it appears to be a raw file: {}", fileId);
                decryptedContent = encryptedContent;
            } else {
                try {
                    // Check format and use appropriate method
                    if (isChunked) {
                        // Older chunked format - use Path directly
                        String storagePath = storageServiceFactory.getStorageService().getFilePath(storageFileName);
                        streamChunkedFileDownload(ctx, Paths.get(storagePath), metadata);
                        return;
                    } else if (isBinary) {
                        // Use Vault directly for binary files
                        try {
                            decryptedContent = vaultService.decryptBinary(fileId, encryptedContent, null);
                            logger.info("Decrypted binary content: {} bytes", decryptedContent != null ? decryptedContent.length : 0);
                        } catch (Exception e) {
                            // For binary files that are images/documents, fall back to raw content
                            if (isImageOrDocument) {
                                logger.warn("Binary decryption failed for image/document, serving raw content: {}", e.getMessage());
                                decryptedContent = encryptedContent; // Fall back to raw content
                            } else {
                                throw e; // Re-throw for other binary types
                            }
                        }
                    } else {
                        // Use Vault directly for text files
                        try {
                            String contentAsString = new String(encryptedContent, StandardCharsets.UTF_8);
                            
                            // If content is already in Vault format, use it directly
                            if (contentAsString.startsWith("vault:v")) {
                                decryptedContent = vaultService.decryptWithKey(fileId, contentAsString, null);
                            } else {
                                // Otherwise convert to Base64 and use Vault format
                                String base64Content = Base64.getEncoder().encodeToString(encryptedContent);
                                decryptedContent = vaultService.decrypt(fileId, base64Content);
                            }
                            
                            logger.info("Decrypted text content: {} bytes", decryptedContent != null ? decryptedContent.length : 0);
                        } catch (Exception e) {
                            // For image/document files with text format, fall back to raw content
                            if (isImageOrDocument) {
                                logger.warn("Text decryption failed for image/document, serving raw content: {}", e.getMessage());
                                decryptedContent = encryptedContent; // Fall back to raw content
                            } else {
                                throw e; // Re-throw for other text types
                            }
                        }
                    }
                    
                    if (decryptedContent == null || decryptedContent.length == 0) {
                        throw new RuntimeException("Decryption failed - no content returned");
                    }
                } catch (Exception e) {
                    String errorMessage = e.getMessage();
                    // Check if it's a "message authentication failed" error
                    boolean isAuthError = false;
                    Throwable cause = e;
                    while (cause != null) {
                        if (cause.getMessage() != null && 
                            (cause.getMessage().contains("message authentication failed") || 
                             cause.getMessage().contains("cipher: message authentication failed"))) {
                            isAuthError = true;
                            break;
                        }
                        cause = cause.getCause();
                    }
                    
                    // For auth failures with image/doc files, serve raw content
                    if ((isAuthError || e.getMessage().contains("Invalid ciphertext")) && isImageOrDocument) {
                        logger.warn("Authentication/decryption failed for file: {}. Will serve content directly.", fileId);
                        decryptedContent = encryptedContent;
                    } else {
                        logger.error("Decryption failed: {}. Will try to serve content directly.", errorMessage);
                        
                        // If the file has a known image/document type extension, try serving it directly
                        if (isImageOrDocument) {
                            logger.warn("Serving file directly without decryption due to decryption failure: {}", originalFilename);
                            decryptedContent = encryptedContent;  // Serve the raw content
                        } else {
                            // For other file types, it's safer to fail
                            sendError(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR, "Decryption failed: " + errorMessage);
                            return;
                        }
                    }
                }
            }
            
            // Stream the content back to the client in chunks to avoid memory pressure
            int chunkSize = 1024 * 1024; // 1MB chunks
            for (int i = 0; i < decryptedContent.length; i += chunkSize) {
                int length = Math.min(chunkSize, decryptedContent.length - i);
                ByteBuf chunk = Unpooled.wrappedBuffer(decryptedContent, i, length);
                ctx.write(new DefaultHttpContent(chunk));
                ctx.flush();
            }
            
            // End the response
            ctx.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT);
            
        } catch (Exception e) {
            logger.error("Failed to process file download", e);
            sendError(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR, "Failed to process file download: " + e.getMessage());
        }
    }
    
    private void streamChunkedFileDownload(ChannelHandlerContext ctx, Path storagePath, Map<String, Object> metadata) throws Exception {
        try (InputStream inputStream = Files.newInputStream(storagePath)) {
            // Read the header size
            StringBuilder headerSizeStr = new StringBuilder();
            int b;
            while ((b = inputStream.read()) != -1 && b != '\n') {
                headerSizeStr.append((char) b);
            }
            if (b == -1) {
                throw new IOException("Invalid file format: missing header size");
            }
            
            int headerSize = Integer.parseInt(headerSizeStr.toString());
            
            // Read and skip the header
            byte[] headerBytes = new byte[headerSize];
            int bytesRead = inputStream.read(headerBytes);
            if (bytesRead != headerSize) {
                throw new IOException("Invalid file format: incomplete header");
            }
            // Skip newline
            inputStream.read();
            
            // Process chunks
            StringBuilder chunkSizeStr = new StringBuilder();
            while ((b = inputStream.read()) != -1) {
                if (b == '\n') {
                    // Process the chunk
                    int chunkSize;
                    try {
                        chunkSize = Integer.parseInt(chunkSizeStr.toString());
                    } catch (NumberFormatException e) {
                        throw new IOException("Invalid chunk size format: " + chunkSizeStr.toString());
                    }
                    
                    // Check if this is a footer
                    if (chunkSize < 256) {  // Typical size for footer metadata
                        byte[] footerBytes = new byte[chunkSize];
                        bytesRead = inputStream.read(footerBytes);
                        if (bytesRead != chunkSize) {
                            throw new IOException("Invalid file format: incomplete footer");
                        }
                        // We've reached the end of chunks
                        break;
                    }
                    
                    // Read the encrypted chunk
                    byte[] encryptedChunk = new byte[chunkSize];
                    bytesRead = inputStream.read(encryptedChunk);
                    if (bytesRead != chunkSize) {
                        throw new IOException("Invalid file format: incomplete chunk");
                    }
                    // Skip newline
                    inputStream.read();
                    
                    // Decrypt the chunk using Vault
                    String fileId = (String) metadata.get("fileId");
                    String base64Ciphertext = Base64.getEncoder().encodeToString(encryptedChunk);
                    byte[] decryptedChunk = vaultService.decryptWithKey(fileId, base64Ciphertext, null);
                    
                    // Stream the decrypted chunk to the client
                    ByteBuf outChunk = Unpooled.wrappedBuffer(decryptedChunk);
                    ctx.writeAndFlush(new DefaultHttpContent(outChunk));
                    
                    // Reset chunk size string for next chunk
                    chunkSizeStr = new StringBuilder();
                } else {
                    chunkSizeStr.append((char) b);
                }
            }
            
            // End the response
            ctx.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT);
            
        } catch (Exception e) {
            logger.error("Error during chunked file download", e);
            sendError(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR, "Error during file download: " + e.getMessage());
        }
    }

    private void sendResponse(ChannelHandlerContext ctx, HttpResponseStatus status, String content) {
        FullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1, 
                status,
                Unpooled.copiedBuffer(content, CharsetUtil.UTF_8));
        
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json; charset=UTF-8");
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
        
        ctx.writeAndFlush(response);
    }
    
    private void sendError(ChannelHandlerContext ctx, HttpResponseStatus status, String message) {
        try {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("code", status.code());
            errorResponse.put("message", message);
            
            String content = new ObjectMapper().writeValueAsString(errorResponse);
            sendResponse(ctx, status, content);
        } catch (JsonProcessingException e) {
            logger.error("Error creating error response", e);
            FullHttpResponse response = new DefaultFullHttpResponse(
                    HttpVersion.HTTP_1_1, 
                    status,
                    Unpooled.copiedBuffer("Error: " + message, CharsetUtil.UTF_8));
            
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
            response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
            
            ctx.writeAndFlush(response);
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("Channel exception caught", cause);
        ctx.close();
    }

    @PostMapping("/files/api/files/upload-from-path")
    public ResponseEntity<Map<String, Object>> handleFileUploadFromPath(
            @RequestHeader("X-File-Path") String filePath,
            @RequestHeader("X-File-Name") String fileName,
            @RequestHeader("X-File-Size") long fileSize,
            @RequestHeader(value = "X-File-Sensitivity", required = false) String sensitivity,
            @RequestHeader(value = "X-File-Value", required = false) String value) {
        
        try {
            // Generate a unique file ID
            String fileId = UUID.randomUUID().toString();
            String storageFilename = fileId + ".enc";
            
            // Process the file
            Path tempFilePath = Paths.get(filePath);
            boolean success = storageServiceFactory.getStorageService().storeFileStreaming(
                storageFilename,
                Files.newInputStream(tempFilePath)
            );
            
            if (success) {
                // Store metadata in Vault
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("fileId", fileId);
                metadata.put("originalFilename", fileName);
                metadata.put("storageFilename", storageFilename);
                metadata.put("fileSize", fileSize);
                metadata.put("timestamp", System.currentTimeMillis());
                metadata.put("sensitivity", sensitivity);
                metadata.put("value", value);
                
                vaultService.storeMetadata(fileId, metadata);
            }
            
            // Clean up the temporary file
            Files.deleteIfExists(tempFilePath);
            
            // Return success response
            Map<String, Object> response = new HashMap<>();
            response.put("status", success ? "success" : "error");
            response.put("message", success ? "File uploaded successfully" : "Failed to upload file");
            response.put("fileId", fileId);
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Error processing file upload from path: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                        "status", "error",
                        "message", "Failed to process file upload: " + e.getMessage()
                    ));
        }
    }
}
