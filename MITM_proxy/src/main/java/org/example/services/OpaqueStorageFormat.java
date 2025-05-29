// package org.example.services;

// import org.example.entities.EncryptionResult;
// import org.example.encryption.AlgorithmSelector;
// import org.example.encryption.EncryptionAlgorithm;
// import org.slf4j.Logger;
// import org.slf4j.LoggerFactory;
// import org.springframework.stereotype.Service;

// import java.util.Base64;
// import java.util.UUID;
// import java.nio.charset.StandardCharsets;
// import java.io.ByteArrayOutputStream;
// import java.io.IOException;
// import java.util.Map;
// import java.util.concurrent.ConcurrentHashMap;
// import java.util.HashMap;
// import java.nio.ByteBuffer;
// import com.fasterxml.jackson.databind.ObjectMapper;

// @Service
// public class OpaqueStorageFormat {
//     private static final Logger logger = LoggerFactory.getLogger(OpaqueStorageFormat.class);
//     private static final String DELIMITER = "||";
//     private static final int MIN_CHUNK_SIZE = 1024 * 1024; // 1MB minimum
//     private static final int MAX_CHUNK_SIZE = 16 * 1024 * 1024; // 16MB maximum
//     private static final int DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024; // 4MB default
//     private static final ConcurrentHashMap<String, byte[]> BINARY_CONTENT_CACHE = new ConcurrentHashMap<>();
//     private static final int MAX_CACHE_ENTRIES = 100;

//     public static class OpaqueStorageResult {
//         private final String fileId;
//         private final String storageFileName;
//         private final String opaqueContent;
//         private final byte[] binaryContent;
//         private final boolean isBinary;

//         private OpaqueStorageResult(String fileId, String storageFileName, String opaqueContent) {
//             this.fileId = fileId;
//             this.storageFileName = storageFileName;
//             this.opaqueContent = opaqueContent;
//             this.binaryContent = null;
//             this.isBinary = false;
//         }

//         private OpaqueStorageResult(String fileId, String storageFileName, byte[] binaryContent) {
//             this.fileId = fileId;
//             this.storageFileName = storageFileName;
//             this.opaqueContent = null;
//             this.binaryContent = binaryContent;
//             this.isBinary = true;
//         }

//         public String getFileId() {
//             return fileId;
//         }

//         public String getStorageFileName() {
//             return storageFileName;
//         }

//         public String getOpaqueContent() {
//             if (isBinary) {
//                 throw new IllegalStateException("Content is binary, use getBinaryContent() instead");
//             }
//             return opaqueContent;
//         }

//         public byte[] getBinaryContent() {
//             if (!isBinary) {
//                 throw new IllegalStateException("Content is not binary, use getOpaqueContent() instead");
//             }
//             return binaryContent;
//         }

//         public boolean isBinary() {
//             return isBinary;
//         }
//     }


//     public static OpaqueStorageResult createOpaqueFormat(
//             byte[] content, 
//             String fileName, 
//             EncryptionService encryptionService,
//             VaultService vaultService) throws Exception {
        
//         String fileId = UUID.randomUUID().toString();
//         String extension = getFileExtension(fileName);
//         String storageFileName = fileId + (extension.isEmpty() ? "" : "." + extension) + ".enc";
        
//         // Determine format based on content type
//         boolean isBinary = isBinaryContent(content);
        
//         if (isBinary) {
//             return createBinaryOpaqueFormat(content, fileId, storageFileName, encryptionService, vaultService);
//         } else {
//             return createTextOpaqueFormat(content, fileId, storageFileName, encryptionService, vaultService);
//         }
//     }

//     private static String getFileExtension(String filename) {
//         if (filename == null || filename.isEmpty() || !filename.contains(".")) {
//             return "";
//         }
//         return filename.substring(filename.lastIndexOf(".") + 1);
//     }
 
//     private static OpaqueStorageResult createTextOpaqueFormat(
//             byte[] content, 
//             String fileId, 
//             String storageFileName, 
//             EncryptionService encryptionService,
//             VaultService vaultService) throws Exception {
        
//         logger.info("Creating text-based opaque format for file ID: {}", fileId);
        
//         // Get the appropriate algorithm
//         AlgorithmSelector.FileProperties props = new AlgorithmSelector.FileProperties(
//             content.length, false, 0, false);
//         EncryptionAlgorithm algorithm = AlgorithmSelector.selectAlgorithm(props);
        
//         // Encrypt the content
//         EncryptionResult result = encryptionService.encrypt(fileId, content, content.length, false, false);
        
//         // Create JSON metadata
//         Map<String, Object> metadata = new HashMap<>();
//         metadata.put("fileId", fileId);
//         metadata.put("storageFileName", storageFileName);
//         metadata.put("timestamp", System.currentTimeMillis());
//         metadata.put("algorithm", algorithm.getName());
//         metadata.put("chunked", false);
//         metadata.put("format", "text");
//         metadata.put("size", content.length);
        
//         // Store metadata in Vault
//         vaultService.storeMetadata(fileId, metadata);
        
//         // Return just the ciphertext without any metadata or padding
//         return new OpaqueStorageResult(fileId, storageFileName, result.getCiphertext());
//     }

//     private int calculateChunkSize(long fileSize) {
//         // For files under 1MB, use minimum chunk size
//         if (fileSize < MIN_CHUNK_SIZE) {
//             return MIN_CHUNK_SIZE;
//         }
        
//         // For files over 1GB, use maximum chunk size
//         if (fileSize > 1024 * 1024 * 1024) {
//             return MAX_CHUNK_SIZE;
//         }
        
//         // For files between 1MB and 1GB, scale chunk size logarithmically
//         double scale = Math.log10(fileSize / (1024.0 * 1024.0)) / Math.log10(1024.0);
//         int chunkSize = (int) (MIN_CHUNK_SIZE * Math.pow(2, scale));
        
//         // Round to nearest power of 2
//         chunkSize = Integer.highestOneBit(chunkSize);
        
//         // Ensure chunk size is within bounds
//         return Math.min(Math.max(chunkSize, MIN_CHUNK_SIZE), MAX_CHUNK_SIZE);
//     }

//     public static OpaqueStorageResult createBinaryOpaqueFormat(
//             byte[] content, 
//             String fileId, 
//             String storageFileName, 
//             EncryptionService encryptionService,
//             VaultService vaultService) throws Exception {
        
//         logger.info("Creating binary opaque format for file ID: {}", fileId);
        
//         // Get the appropriate algorithm (prefer ChaCha20 for large files)
//         AlgorithmSelector.FileProperties props = new AlgorithmSelector.FileProperties(
//             content.length, false, 0, false);
//         EncryptionAlgorithm algorithm = AlgorithmSelector.selectAlgorithm(props);
        
//         // Stream through encryption in chunks
//         ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

//         Map<String, Object> metadata = vaultService.getMetadata(fileId);

//         String key = (String) metadata.get("keyName");
        
//         // Process content in chunks
//         int chunkCount = 0;
//         for (int offset = 0; offset < content.length; offset += DEFAULT_CHUNK_SIZE) {
//             int chunkSize = Math.min(DEFAULT_CHUNK_SIZE, content.length - offset);
            
//             // Encrypt this chunk directly using algorithm implementation
//             byte[] encryptedChunk = algorithm.encrypt(content, offset, chunkSize, key);
            
//             // Write chunk size (including authentication tag and nonce) and chunk
//             outputStream.write(ByteBuffer.allocate(4).putInt(encryptedChunk.length).array());
//             outputStream.write(encryptedChunk);
            
//             chunkCount++;
//         }
        
//         // Create storage result
//         byte[] binaryContent = outputStream.toByteArray();

//         metadata.put("fileId", fileId);
//         metadata.put("storageFileName", storageFileName);
//         metadata.put("timestamp", System.currentTimeMillis());
//         metadata.put("algorithm", algorithm.getName());
//         metadata.put("chunked", true);
//         metadata.put("format", "binary");
//         metadata.put("size", content.length);
//         metadata.put("chunkCount", chunkCount);
//         metadata.put("chunkSize", DEFAULT_CHUNK_SIZE);
        
//         // Store metadata in Vault
//         vaultService.storeMetadata(fileId, metadata);
        
//         // Optionally cache for small enough content
//         if (binaryContent.length < 10 * DEFAULT_CHUNK_SIZE && BINARY_CONTENT_CACHE.size() < MAX_CACHE_ENTRIES) {
//             BINARY_CONTENT_CACHE.put(fileId, binaryContent);
//         }
        
//         return new OpaqueStorageResult(fileId, storageFileName, binaryContent);
//     }

//     public static byte[] extractContent(
//             byte[] data,
//             String fileId,
//             EncryptionService encryptionService,
//             VaultService vaultService) throws Exception {
        
//         // Try to determine the format based on the first few bytes
//         if (data.length > 4) {
//             // Binary format starts with a 4-byte integer header size
//             ByteBuffer buffer = ByteBuffer.wrap(data, 0, 4);
//             int headerSize = buffer.getInt();
            
//             // If header size is reasonable (JSON headers are typically < 1KB)
//             if (headerSize > 0 && headerSize < 1024 && headerSize < data.length - 4) {
//                 try {
//                     // Try to extract as binary
//                     return extractBinaryContent(data, fileId, encryptionService, vaultService);
//                 } catch (Exception e) {
//                     logger.warn("Failed to extract as binary, trying text format", e);
//                 }
//             }
//         }
        
//         // Fall back to text format
//         return extractTextContent(new String(data, StandardCharsets.UTF_8), encryptionService, vaultService);
//     }
    

//     public static byte[] extractTextContent(
//             String opaqueContent, 
//             EncryptionService encryptionService, 
//             VaultService vaultService) throws Exception {
        
//         try {
//             // Parse the opaque content
//             Map<String, Object> opaque = new ObjectMapper().readValue(opaqueContent, Map.class);
//             String fileId = (String) opaque.get("fileId");
//             String ciphertext = (String) opaque.get("ciphertext");
//             String format = (String) opaque.getOrDefault("format", "text");
            
//             logger.info("Extracting content from text-based opaque format for file ID: {}", fileId);
            
//             // Decrypt the content
//             Map<String, Object> metadata = vaultService.getMetadata(fileId);
//             String algorithm = (String) metadata.get("algorithm");
//             byte[] encryptedBytes = ciphertext.getBytes(StandardCharsets.UTF_8);
//             byte[] decryptedContent = encryptionService.decrypt(fileId, encryptedBytes, algorithm);
//             return decryptedContent;
//         } catch (Exception e) {
//             logger.error("Failed to extract content from opaque format", e);
//             throw new RuntimeException("Failed to extract content from opaque format", e);
//         }
//     }

//     public static byte[] extractBinaryContent(
//             byte[] binaryData,
//             String fileId,
//             EncryptionService encryptionService,
//             VaultService vaultService) throws Exception {
        
//         try {
//             ByteBuffer buffer = ByteBuffer.wrap(binaryData);
            
//             // Get metadata from Vault
//             Map<String, Object> metadata = vaultService.getMetadata(fileId);
//             if (metadata == null) {
//                 throw new RuntimeException("No metadata found for file: " + fileId);
//             }
            
//             String algorithmName = (String) metadata.get("algorithm");
//             int originalSize = ((Number) metadata.get("size")).intValue();
//             int chunkSize = ((Number) metadata.getOrDefault("chunkSize", DEFAULT_CHUNK_SIZE)).intValue();
            
//             logger.info("Extracting content from binary opaque format for file ID: {}", fileId);
            
//             // Get algorithm
//             EncryptionAlgorithm algorithm = AlgorithmSelector.getAlgorithmByName(algorithmName);
            
            
//             // Initialize result buffer
//             ByteArrayOutputStream outputStream = new ByteArrayOutputStream(originalSize);

//             String key = (String) metadata.get("keyName");
            
//             // Process chunks
//             while (buffer.hasRemaining()) {
//                 // Read chunk size (including authentication tag and nonce)
//                 int encryptedChunkSize = buffer.getInt();
                
//                 // Read encrypted chunk
//                 byte[] encryptedChunk = new byte[encryptedChunkSize];
//                 buffer.get(encryptedChunk);
                
//                 // Decrypt using the algorithm directly
//                 byte[] decryptedChunk = algorithm.decrypt(encryptedChunk, key);
//                 outputStream.write(decryptedChunk);
//             }
            
//             byte[] result = outputStream.toByteArray();
//             if (result.length != originalSize) {
//                 logger.warn("Decrypted size mismatch: expected {} bytes, got {} bytes", originalSize, result.length);
//             }
//             logger.info("Successfully decrypted binary content: {} bytes", result.length);
//             return result;
//         } catch (Exception e) {
//             logger.error("Failed to extract content from binary opaque format", e);
//             throw new RuntimeException("Failed to extract content from binary opaque format", e);
//         }
//     }
    
   
//     public static void clearCache() {
//         BINARY_CONTENT_CACHE.clear();
//         logger.info("Cleared binary content cache");
//     }
    

//     public static Map<String, Object> getCacheStats() {
//         Map<String, Object> stats = new HashMap<>();
//         stats.put("cacheSize", BINARY_CONTENT_CACHE.size());
//         stats.put("maxCacheEntries", MAX_CACHE_ENTRIES);
//         return stats;
//     }

//     public static boolean isBinaryContent(byte[] content) {
//         if (content == null || content.length == 0) return false;
    
//         // Check for PNG signature (first 8 bytes)
//         if (content.length >= 8) {
//             byte[] pngSignature = new byte[]{(byte)0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
//             boolean isPng = true;
//             for (int i = 0; i < 8; i++) {
//                 if (content[i] != pngSignature[i]) {
//                     isPng = false;
//                     break;
//                 }
//             }
//             if (isPng) return true;
//         }
        
//         // Check for other binary indicators
//         int nonPrintable = 0;
//         for (int i = 0; i < Math.min(content.length, 1000); i++) {
//             byte b = content[i];
//             if (b < 32 && b != 9 && b != 10 && b != 13) { // Non-printable ASCII
//                 nonPrintable++;
//             }
//         }
        
//         // If more than 10% of the first 1000 bytes are non-printable, consider it binary
//         return nonPrintable > 100;
//     }
// } 