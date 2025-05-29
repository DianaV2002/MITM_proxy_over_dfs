package org.example.services;

import org.example.config.ProxyConfig;
import org.example.encryption.AlgorithmSelector;
import org.example.encryption.EncryptionAlgorithm;
import org.example.entities.EncryptionResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.nio.charset.StandardCharsets;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.nio.ByteBuffer;

@Service
public class EncryptionService {
    private static final Logger logger = LoggerFactory.getLogger(EncryptionService.class);
    private static final int MIN_CHUNK_SIZE = 1024 * 1024; // 1MB minimum
    private static final int MAX_CHUNK_SIZE = 16 * 1024 * 1024; // 16MB maximum
    private static final int DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024; // 4MB default
    private static final int BUFFER_SIZE = 4 * 1024 * 1024; // 4MB buffer
    private final VaultService vaultService;
    private final ProxyConfig config;
    private final RestTemplate restTemplate;

    public EncryptionService() {
        this.config = ProxyConfig.getInstance();
        this.vaultService = new VaultService();
        this.restTemplate = new RestTemplate();
    }

    public EncryptionService(VaultService vaultService) {
        this.vaultService = vaultService;
        this.config = ProxyConfig.getInstance();
        this.restTemplate = new RestTemplate();
    }

    private void recordPerformance(String operation, int inputSize, int outputSize) {
        try {
            Map<String, Object> metric = new HashMap<>();
            metric.put("method", operation);
            metric.put("time", TimeUnit.NANOSECONDS.toMillis(System.nanoTime()));
            metric.put("size", inputSize);
            metric.put("success", true);
            
            restTemplate.postForObject(
                "http://localhost:8080/visualization/api/performance",
                metric,
                Map.class
            );
        } catch (Exception e) {
            logger.warn("Failed to record performance metrics", e);
            // Don't throw exception - this is non-critical functionality
        }
    }

    public EncryptionResult encrypt(String fileId, byte[] data, long fileSize, boolean isSensitive,
                                 boolean isHighValue) throws Exception {
        // For small files, use the existing method
        if (fileSize <= DEFAULT_CHUNK_SIZE) {
            return encryptChunk(fileId, data, fileSize, isSensitive, isHighValue);
        }
        
        // For large files, use chunked encryption
        try (InputStream inputStream = new java.io.ByteArrayInputStream(data)) {
            return encryptChunked(fileId, inputStream, fileSize, isSensitive, isHighValue);
        }
    }

    public EncryptionResult encrypt(String fileId, InputStream inputStream, long fileSize, boolean isSensitive,
                                 boolean isHighValue) throws Exception {
        // Always use chunked encryption for InputStream
        return encryptChunked(fileId, inputStream, fileSize, isSensitive, isHighValue);
    }

    private EncryptionResult encryptChunk(String fileId, byte[] data, long fileSize, boolean isSensitive,
                                       boolean isHighValue) throws Exception {
        long accessCount = 0;
        AlgorithmSelector.FileProperties props = new AlgorithmSelector.FileProperties(
            fileSize, isSensitive, accessCount, isHighValue
        );

        EncryptionAlgorithm algorithm = AlgorithmSelector.selectAlgorithm(props);
        logger.info("Selected encryption algorithm: {}", algorithm.getName());

        byte[] encrypted = vaultService.encryptWithKey(fileId, algorithm, data);
        EncryptionResult result = new EncryptionResult();
        result.setFileId(fileId);
        result.setCiphertext(Base64.getEncoder().encodeToString(encrypted));
        result.setAlgorithm(algorithm.getName());
        result.setKeySize(algorithm.getKeySize());
        result.setMode(algorithm.getMode());
        result.setAuthenticated(algorithm.isAuthenticated());
        return result;
    }

    private EncryptionResult encryptChunked(String fileId, InputStream inputStream, long fileSize, 
                                         boolean isSensitive, boolean isHighValue) throws Exception {
        long accessCount = 0;
        AlgorithmSelector.FileProperties props = new AlgorithmSelector.FileProperties(
            fileSize, isSensitive, accessCount, isHighValue
        );

        EncryptionAlgorithm algorithm = AlgorithmSelector.selectAlgorithm(props);
        logger.info("Selected encryption algorithm: {} for chunked encryption", algorithm.getName());

        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[DEFAULT_CHUNK_SIZE];
            int bytesRead;
            long totalBytesRead = 0;
            boolean firstChunk = true;

            while ((bytesRead = inputStream.read(buffer)) != -1) {
                totalBytesRead += bytesRead;
                byte[] chunk = new byte[bytesRead];
                System.arraycopy(buffer, 0, chunk, 0, bytesRead);
                
                byte[] encrypted = vaultService.encryptWithKey(fileId, algorithm, chunk);
                EncryptionResult chunkResult = new EncryptionResult();
                chunkResult.setFileId(fileId);
                chunkResult.setCiphertext(Base64.getEncoder().encodeToString(encrypted));
                chunkResult.setAlgorithm(algorithm.getName());
                chunkResult.setKeySize(algorithm.getKeySize());
                chunkResult.setMode(algorithm.getMode());
                chunkResult.setAuthenticated(algorithm.isAuthenticated());
                
                // Write the chunk with delimiter
                if (!firstChunk) {
                    outputStream.write("||".getBytes(StandardCharsets.UTF_8));
                }
                outputStream.write(chunkResult.getCiphertext().getBytes(StandardCharsets.UTF_8));
                firstChunk = false;
                
                logger.debug("Processed chunk of size {} bytes (total: {}/{})", 
                    bytesRead, totalBytesRead, fileSize);
            }

            EncryptionResult result = new EncryptionResult();
            result.setFileId(fileId);
            result.setCiphertext(outputStream.toString(StandardCharsets.UTF_8));
            result.setAlgorithm(algorithm.getName());
            result.setKeySize(algorithm.getKeySize());
            result.setMode(algorithm.getMode());
            result.setAuthenticated(algorithm.isAuthenticated());

            return result;
        }
    }

    private int calculateChunkSize(long fileSize) {
        // For files under 1MB, use minimum chunk size
        if (fileSize < MIN_CHUNK_SIZE) {
            return MIN_CHUNK_SIZE;
        }
        
        // For files over 1GB, use maximum chunk size
        if (fileSize > 1024 * 1024 * 1024) {
            return MAX_CHUNK_SIZE;
        }
        
        // For files between 1MB and 1GB, scale chunk size logarithmically
        double scale = Math.log10(fileSize / (1024.0 * 1024.0)) / Math.log10(1024.0);
        int chunkSize = (int) (MIN_CHUNK_SIZE * Math.pow(2, scale));
        
        // Round to nearest power of 2
        chunkSize = Integer.highestOneBit(chunkSize);
        
        // Ensure chunk size is within bounds
        return Math.min(Math.max(chunkSize, MIN_CHUNK_SIZE), MAX_CHUNK_SIZE);
    }

    public void encryptChunkedStream(
        String fileId,
        InputStream inputStream,
        OutputStream outputStream,
        long fileSize,
        boolean isSensitive,
        boolean isHighValue
    ) throws Exception {
        long accessCount = 0;
        AlgorithmSelector.FileProperties props = new AlgorithmSelector.FileProperties(fileSize, isSensitive, accessCount, isHighValue);
        EncryptionAlgorithm algorithm = AlgorithmSelector.selectAlgorithm(props);

        logger.info("Starting streaming encryption for file: {} with algorithm: {}", fileId, algorithm.getName());

        int chunkSize = calculateChunkSize(fileSize);
        logger.info("Using dynamic chunk size: {} bytes for file size: {} bytes", chunkSize, fileSize);
        
        byte[] buffer = new byte[chunkSize];
        int bytesRead;
        long totalBytes = 0;
        long startTime = System.nanoTime();

        // Process chunks
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            totalBytes += bytesRead;
            byte[] chunk = new byte[bytesRead];
            System.arraycopy(buffer, 0, chunk, 0, bytesRead);
            
            byte[] encrypted = vaultService.encryptWithKey(fileId, algorithm, chunk);
            EncryptionResult chunkResult = new EncryptionResult();
            chunkResult.setFileId(fileId);
            chunkResult.setCiphertext(Base64.getEncoder().encodeToString(encrypted));
            chunkResult.setAlgorithm(algorithm.getName());
            chunkResult.setKeySize(algorithm.getKeySize());
            chunkResult.setMode(algorithm.getMode());
            chunkResult.setAuthenticated(algorithm.isAuthenticated());
            
            // Write just the ciphertext without any metadata or padding
            outputStream.write(chunkResult.getCiphertext().getBytes(StandardCharsets.UTF_8));
            
            logger.debug("Processed chunk of size {} bytes (total: {}/{})", 
                bytesRead, totalBytes, fileSize);
        }

        long endTime = System.nanoTime();
        long duration = TimeUnit.NANOSECONDS.toMillis(endTime - startTime);
        logger.info("Completed streaming encryption in {} ms for file: {}", duration, fileId);
    }

    public void decryptChunkedStream(String fileId, InputStream inputStream, OutputStream outputStream) throws Exception {
        logger.info("Starting streamed decryption for file: {}", fileId);
        
        try {
            // Read header size
            byte[] headerSizeBytes = new byte[4];
            int bytesRead = inputStream.read(headerSizeBytes);
            if (bytesRead != 4) {
                throw new IOException("Invalid file format: missing header size");
            }
            int headerSize = ByteBuffer.wrap(headerSizeBytes).getInt();
            
            // Read header
            byte[] headerBytes = new byte[headerSize];
            bytesRead = inputStream.read(headerBytes);
            if (bytesRead != headerSize) {
                throw new IOException("Invalid file format: incomplete header");
            }
            
            long startTime = System.nanoTime();
            long totalBytes = 0;
            int chunkSize;
            byte[] chunkSizeBytes = new byte[4];
            
            // Process chunks with memory-efficient streaming
            while ((bytesRead = inputStream.read(chunkSizeBytes)) != -1) {
                if (bytesRead != 4) {
                    throw new IOException("Invalid file format: incomplete chunk size");
                }
                
                chunkSize = ByteBuffer.wrap(chunkSizeBytes).getInt();
                
                // Check if this is a footer
                if (chunkSize < 256) {  // Typical size for footer metadata
                    byte[] footerBytes = new byte[chunkSize];
                    bytesRead = inputStream.read(footerBytes);
                    if (bytesRead != chunkSize) {
                        throw new IOException("Invalid file format: incomplete footer");
                    }
                    break;
                }
                
                // Process chunk in smaller sub-chunks to avoid memory issues
                int subChunkSize = Math.min(chunkSize, 1024 * 1024); // 1MB sub-chunks
                byte[] subChunk = new byte[subChunkSize];
                int remaining = chunkSize;
                
                while (remaining > 0) {
                    int currentSubChunkSize = Math.min(remaining, subChunkSize);
                    bytesRead = inputStream.read(subChunk, 0, currentSubChunkSize);
                    if (bytesRead != currentSubChunkSize) {
                        throw new IOException("Invalid file format: incomplete chunk");
                    }
                    
                    // Decrypt and write the sub-chunk
                    try {
                        // The data is Base64 encoded, so decode it first
                        byte[] decodedChunk = Base64.getDecoder().decode(subChunk);
                        // Convert the decoded bytes to a string for the VaultService
                        String ciphertext = new String(decodedChunk, StandardCharsets.UTF_8);
                        byte[] decrypted = vaultService.decrypt(fileId, ciphertext);
                        outputStream.write(decrypted);
                        totalBytes += decrypted.length;
                    } catch (Exception e) {
                        logger.warn("Failed to decrypt chunk for file: {}, skipping. Error: {}", fileId, e.getMessage());
                    }
                    
                    remaining -= currentSubChunkSize;
                }
            }
            
            outputStream.flush();
            long endTime = System.nanoTime();
            double throughput = (totalBytes / (1024.0 * 1024.0)) / ((endTime - startTime) / 1_000_000_000.0);
            logger.info("Finished streamed decryption for file: {}, total bytes: {}, throughput: {:.2f} MB/s", 
                fileId, totalBytes, throughput);
            
        } finally {
            try {
                inputStream.close();
            } catch (IOException e) {
                logger.warn("Error closing input stream: {}", e.getMessage());
            }
        }
    }

    private boolean isBinaryContent(byte[] content) {
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

    private byte[] decryptBinary(String fileId, byte[] encryptedData, String algorithmName) {
        try {
            // Get the appropriate encryption algorithm
            EncryptionAlgorithm algorithm = AlgorithmSelector.getAlgorithmByName(algorithmName);
            if (algorithm == null) {
                throw new RuntimeException("Unsupported algorithm: " + algorithmName);
            }

            Map<String, Object> metadata = vaultService.getMetadata(fileId);
            String key = (String) metadata.get("keyName");

            // For authenticated encryption (AES-GCM, ChaCha20-Poly1305), ensure we have enough data
            if (algorithm.isAuthenticated()) {
                int minLength = 0;
                if ("AES-GCM".equals(algorithmName)) {
                    minLength = 12 + 16; // IV (12 bytes) + tag (16 bytes)
                } else if ("ChaCha20-Poly1305".equals(algorithmName)) {
                    minLength = 12 + 16; // Nonce (12 bytes) + tag (16 bytes)
                }
                
                if (encryptedData.length < minLength) {
                    throw new RuntimeException("Encrypted data too short for " + algorithmName + 
                        " (expected at least " + minLength + " bytes)");
                }
            }

            // Decrypt the data
            byte[] decrypted = vaultService.decryptBinary(fileId, encryptedData, key);
            if (decrypted == null) {
                throw new RuntimeException("Decryption returned null");
            }

            logger.info("Successfully decrypted binary data: {} bytes", decrypted.length);
            return decrypted;
        } catch (Exception e) {
            logger.error("Failed to decrypt binary data", e);
            throw new RuntimeException("Failed to decrypt binary data", e);
        }
    }

    private byte[] decryptText(String fileId, byte[] encryptedData, String algorithmName) {
        try {
            // Get the appropriate encryption algorithm
            EncryptionAlgorithm algorithm = AlgorithmSelector.getAlgorithmByName(algorithmName);
            if (algorithm == null) {
                throw new RuntimeException("Unsupported algorithm: " + algorithmName);
            }

            Map<String, Object> metadata = vaultService.getMetadata(fileId);
            String key = (String) metadata.get("keyName");
            
            // Log the actual encrypted data
            logger.info("Decrypting text file: {} with algorithm: {}", fileId, algorithmName);
            logger.info("Encrypted data for file {}: {} bytes", fileId, encryptedData.length);
            
            // Check if this looks like binary data incorrectly treated as text
            boolean looksLikeBinary = false;
            int nonPrintableChars = 0;
            for (int i = 0; i < Math.min(encryptedData.length, 100); i++) {
                if (encryptedData[i] < 32 && encryptedData[i] != 9 && encryptedData[i] != 10 && encryptedData[i] != 13) {
                    nonPrintableChars++;
                }
            }
            if (nonPrintableChars > 10) {
                logger.warn("Data for file {} appears to be binary but is being processed as text", fileId);
                looksLikeBinary = true;
            }
            
            // For authenticated encryption (AES-GCM, ChaCha20-Poly1305), ensure we have enough data
            if (algorithm.isAuthenticated()) {
                int minLength = 0;
                if ("AES-GCM".equals(algorithmName)) {
                    minLength = 12 + 16; // IV (12 bytes) + tag (16 bytes)
                } else if ("ChaCha20-Poly1305".equals(algorithmName)) {
                    minLength = 12 + 16; // Nonce (12 bytes) + tag (16 bytes)
                }
                
                if (encryptedData.length < minLength) {
                    throw new RuntimeException("Encrypted data too short for " + algorithmName + 
                        " (expected at least " + minLength + " bytes, got " + encryptedData.length + " bytes)");
                }
            }

            // Check if data is already in Vault format
            String dataAsString = new String(encryptedData, StandardCharsets.UTF_8);
            if (dataAsString.startsWith("vault:v")) {
                // Data is already in proper format, use it directly
                logger.info("Data is already in Vault format, using directly");
                return vaultService.decrypt(fileId, dataAsString);
            }
            
            // Otherwise, encode to base64 for Vault API
            String base64Content;
            
            // Try to decode as Base64 first - if it's valid Base64, it might already be ciphertext
            try {
                // Just test if this is valid Base64 by trying to decode it
                Base64.getDecoder().decode(dataAsString);
                // If successful, this is likely already Base64 encoded ciphertext
                base64Content = dataAsString;
                logger.debug("Data appears to be Base64 encoded already, using as is");
            } catch (IllegalArgumentException e) {
                // Not valid Base64, so this is likely raw binary data that needs encoding
                logger.debug("Data is not valid Base64, encoding raw bytes to Base64");
                base64Content = Base64.getEncoder().encodeToString(encryptedData);
            }
            
            logger.debug("Prepared content for decryption: {} chars", base64Content.length());

            // Decrypt the data using the Base64 string
            byte[] decrypted = vaultService.decrypt(fileId, base64Content);
            if (decrypted == null) {
                throw new RuntimeException("Decryption returned null");
            }

            logger.info("Successfully decrypted text data: {} bytes", decrypted.length);
            return decrypted;
        } catch (Exception e) {
            logger.error("Failed to decrypt text data", e);
            throw new RuntimeException("Failed to decrypt text data", e);
        }
    }

    public byte[] decrypt(String fileId, byte[] encryptedData, String algorithmName) {
        try {
            // Get metadata to determine if this is binary or text
            Map<String, Object> metadata = vaultService.getMetadata(fileId);
            if (metadata == null) {
                throw new RuntimeException("No metadata found for file: " + fileId);
            }

            // First check for common file signatures that would indicate raw files
            boolean seemsToBeRawFile = false;
            if (encryptedData.length >= 4) {
                // PNG signature
                if (encryptedData.length >= 8 && 
                    encryptedData[0] == (byte)0x89 && encryptedData[1] == (byte)0x50 && 
                    encryptedData[2] == (byte)0x4E && encryptedData[3] == (byte)0x47 &&
                    encryptedData[4] == (byte)0x0D && encryptedData[5] == (byte)0x0A &&
                    encryptedData[6] == (byte)0x1A && encryptedData[7] == (byte)0x0A) {
                    logger.warn("Data for file {} appears to be a raw PNG file (not encrypted)", fileId);
                    seemsToBeRawFile = true;
                }
                // JPEG signature
                else if (encryptedData[0] == (byte)0xFF && encryptedData[1] == (byte)0xD8 && 
                        encryptedData[2] == (byte)0xFF) {
                    logger.warn("Data for file {} appears to be a raw JPEG file (not encrypted)", fileId);
                    seemsToBeRawFile = true;
                }
                // PDF signature
                else if (encryptedData[0] == (byte)0x25 && encryptedData[1] == (byte)0x50 && 
                        encryptedData[2] == (byte)0x44 && encryptedData[3] == (byte)0x46) {
                    logger.warn("Data for file {} appears to be a raw PDF file (not encrypted)", fileId);
                    seemsToBeRawFile = true;
                }
            }

            if (seemsToBeRawFile) {
                // If it's a raw file, just return it as is
                logger.info("Returning raw file data for file: {} ({} bytes)", fileId, encryptedData.length);
                return encryptedData;
            }
            
            // Check if the data is binary
            boolean isBinary = Boolean.TRUE.equals(metadata.get("isBinary"));
            String originalFilename = (String) metadata.get("originalFilename");
            
            // If filename suggests image/document but format isn't explicitly marked as binary
            if (!isBinary && originalFilename != null && 
               (originalFilename.toLowerCase().endsWith(".jpg") || 
                originalFilename.toLowerCase().endsWith(".jpeg") || 
                originalFilename.toLowerCase().endsWith(".png") || 
                originalFilename.toLowerCase().endsWith(".pdf") || 
                originalFilename.toLowerCase().endsWith(".doc") || 
                originalFilename.toLowerCase().endsWith(".docx"))) {
                logger.info("File has image/document extension, treating as binary: {}", originalFilename);
                isBinary = true;
            }
            
            logger.info("Decrypting {} file: {} with algorithm: {}", isBinary ? "binary" : "text", fileId, algorithmName);

            // For authenticated encryption, log the data length
            EncryptionAlgorithm algorithm = AlgorithmSelector.getAlgorithmByName(algorithmName);
            if (algorithm != null && algorithm.isAuthenticated()) {
                logger.debug("Encrypted data length: {} bytes", encryptedData.length);
            }

            // Check if data is Vault format already
            String dataAsString = new String(encryptedData, StandardCharsets.UTF_8);
            if (dataAsString.startsWith("vault:v")) {
                // Data is already in Vault format, use it directly
                logger.info("Data is in Vault format, using directly");
                return vaultService.decryptWithKey(fileId, dataAsString, null);
            }
            
            // The data is likely raw encrypted bytes, encode to Base64 for Vault API
            String base64Content = Base64.getEncoder().encodeToString(encryptedData);
            
            if (isBinary) {
                // For binary, use decryptWithKey directly with the Base64 content
                return vaultService.decryptWithKey(fileId, "vault:v1:" + base64Content, null);
            } else {
                // For text, use decrypt which handles text-specific processing
                return vaultService.decrypt(fileId, base64Content);
            }
        } catch (Exception e) {
            logger.error("Failed to decrypt file: {}", fileId, e);
            
            // For images/documents, return the raw data as fallback
            String originalFilename = null;
            try {
                Map<String, Object> metadata = vaultService.getMetadata(fileId);
                if (metadata != null) {
                    originalFilename = (String) metadata.get("originalFilename");
                }
            } catch (Exception ignored) {}
            
            if (originalFilename != null && 
               (originalFilename.toLowerCase().endsWith(".jpg") || 
                originalFilename.toLowerCase().endsWith(".jpeg") || 
                originalFilename.toLowerCase().endsWith(".png") || 
                originalFilename.toLowerCase().endsWith(".pdf"))) {
                logger.warn("Decryption failed but file appears to be an image/document. Returning raw content: {}", originalFilename);
                return encryptedData;
            }
            
            throw new RuntimeException("Failed to decrypt file: " + fileId, e);
        }
    }

    public byte[] decryptBinary(String fileId, String ciphertext, String algorithm) {
        try {
            // Normalize algorithm name
            if ("Chacha20-Poly1305".equals(algorithm)) {
                algorithm = "ChaCha20-Poly1305";
            }
            
            // Get metadata from Vault
            Map<String, Object> metadata = vaultService.getMetadata(fileId);
            if (metadata == null) {
                throw new RuntimeException("No metadata found for file: " + fileId);
            }
            
            // Get the key from metadata
            String keyName = (String) metadata.get("keyName");
            if (keyName == null) {
                throw new RuntimeException("No key name found in metadata for file: " + fileId);
            }
            
            
            logger.info("Decrypting binary file: {} with algorithm: {}", fileId, algorithm);
            byte[] decryptedBytes = vaultService.decryptWithKey(fileId, ciphertext, keyName);
            if (decryptedBytes == null) {
                throw new RuntimeException("Decryption failed: null result for file: " + fileId);
            }
            logger.info("Successfully decrypted binary file: {} ({} bytes)", fileId, decryptedBytes.length);
            return decryptedBytes;
        } catch (Exception e) {
            logger.error("Failed to decrypt binary file: {}", fileId, e);
            throw new RuntimeException("Failed to decrypt binary file: " + fileId, e);
        }
    }
    
    public void rotateKey(EncryptionAlgorithm algorithm) throws Exception {
        try {
            vaultService.rotateKey(algorithm);
        } catch (Exception e) {
            logger.error("Key rotation failed", e);
            throw new RuntimeException("Key rotation failed", e);
        }
    }

    // New method: chunked encryption that returns ciphertext as a string for storage
    public String encryptChunkedStreamToString(String fileId, InputStream inputStream, long fileSize, boolean isSensitive, boolean isHighValue, EncryptionAlgorithm algorithm) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int chunkSize = calculateChunkSize(fileSize);
        byte[] buffer = new byte[chunkSize];
        int bytesRead;
        boolean firstChunk = true;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] chunk = new byte[bytesRead];
            System.arraycopy(buffer, 0, chunk, 0, bytesRead);
            byte[] encrypted = vaultService.encryptWithKey(fileId, algorithm, chunk);
            String chunkCiphertext = new String(encrypted, StandardCharsets.UTF_8);
            if (!firstChunk) {
                outputStream.write("||".getBytes(StandardCharsets.UTF_8));
            }
            outputStream.write(chunkCiphertext.getBytes(StandardCharsets.UTF_8));
            firstChunk = false;
        }
        return outputStream.toString(StandardCharsets.UTF_8);
    }
}
