package org.example.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.example.config.ProxyConfig;
import org.example.entities.EncryptionResult;
import org.example.encryption.EncryptionAlgorithm;
import org.example.encryption.AESGCMAlgorithm;
import org.example.encryption.Chacha20Poly1305Algorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import org.json.JSONObject;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.HttpClientErrorException;

import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.net.URLEncoder;
import org.springframework.http.HttpEntity;

@Service
public class VaultService {
    private static final Logger logger = LoggerFactory.getLogger(VaultService.class);
    private static final String TRANSIT_KEY_PATH = "transit/keys";
    private final ProxyConfig config;
    private String token;
    private CloseableHttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;
    private static final String TRANSIT_ENCRYPT_PATH = "transit/encrypt";
    private static final String TRANSIT_DECRYPT_PATH = "transit/decrypt";
    private static final String METADATA_PATH = "secret/data/metadata";
    private static final String AES_KEY_NAME = "aes-encryption-key";
    private static final String CHACHA_KEY_NAME = "chacha-encryption-key";
    private static final String OUTER_ENCRYPTION_KEY = "outer-encryption-key";
    private static final int LARGE_FILE_THRESHOLD = 1024 * 1024; // 1MB threshold for large files
    private VaultTemplate vaultTemplate;
    
    // Cache for transit keys and metadata
    private final Map<String, byte[]> transitKeyCache = new ConcurrentHashMap<>();
    private final Map<String, Long> transitKeyCacheTimestamps = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Object>> metadataCache = new ConcurrentHashMap<>();
    private final Map<String, Long> metadataCacheTimestamps = new ConcurrentHashMap<>();
    private static final long CACHE_TTL_MILLIS = TimeUnit.MINUTES.toMillis(5); // 5 minute TTL for cache entries
    private final AtomicLong cacheHits = new AtomicLong(0);
    private final AtomicLong cacheMisses = new AtomicLong(0);

    public String getToken() {
        return token;
    }

    public VaultService() {
        this.config = ProxyConfig.getInstance();
        this.objectMapper = new ObjectMapper();
        this.restTemplate = new RestTemplate();
        try {
            initializeVaultClient();
            // Initialize both transit keys with proper KMS configuration
            initializeTransitKey(new AESGCMAlgorithm(), AES_KEY_NAME);
            initializeTransitKey(new Chacha20Poly1305Algorithm(), CHACHA_KEY_NAME);
            testVaultConnection();
        } catch (Exception e) {
            logger.error("Failed to initialize Vault client", e);
            throw new RuntimeException("Failed to initialize Vault client", e);
        }
    }

    private void initializeVaultClient() throws Exception {
        String vaultAddress = config.getVaultAddress();
        logger.info("Initializing Vault client with address: {}", vaultAddress);
        
        if (vaultAddress == null || vaultAddress.trim().isEmpty()) {
            throw new IllegalStateException("Vault address is not configured");
        }

        VaultEndpoint vaultEndpoint = VaultEndpoint.create(
            URI.create(vaultAddress).getHost(),
            URI.create(vaultAddress).getPort()
        );
        vaultEndpoint.setScheme(URI.create(vaultAddress).getScheme());
        logger.info("Created Vault endpoint: {}:{}", vaultEndpoint.getHost(), vaultEndpoint.getPort());

        String authMethod = config.getVaultAuthMethod();
        ClientAuthentication clientAuthentication;
        
        if ("token".equals(authMethod)) {
            token = config.getVaultToken();
            if (token == null || token.trim().isEmpty()) {
                throw new IllegalStateException("Vault token is not configured");
            }
            logger.info("Using token authentication");
            logger.info("Token prefix: {}", token.substring(0, Math.min(10, token.length())) + "...");
            clientAuthentication = new TokenAuthentication(token);
        } else if ("approle".equals(authMethod)) {
            String roleId = config.getVaultRoleId();
            if (roleId == null || roleId.trim().isEmpty()) {
                throw new IllegalStateException("Vault role ID is not configured");
            }
            logger.info("Using AppRole authentication with role ID: {}", roleId);
            
            // Generate a new secret ID
            String secretId = generateSecretId();
            if (secretId == null || secretId.trim().isEmpty()) {
                throw new IllegalStateException("Failed to generate secret ID");
            }
            
            // Authenticate with AppRole
            authenticateWithAppRole(roleId, secretId);
            clientAuthentication = new TokenAuthentication(token);
        } else {
            throw new IllegalStateException("Unsupported authentication method: " + authMethod);
        }

        try {
            vaultTemplate = new VaultTemplate(vaultEndpoint, clientAuthentication);
            logger.info("Successfully initialized Vault client");
            
            // Test the token permissions
            //testTokenPermissions();
        } catch (Exception e) {
            logger.error("Failed to initialize Vault client: {}", e.getMessage(), e);
            if (e instanceof HttpClientErrorException.Forbidden) {
                logger.error("Token permissions check failed. Current token: {}", 
                    token != null ? token.substring(0, Math.min(10, token.length())) + "..." : "null");
                throw new RuntimeException("Vault token is invalid or lacks required permissions. Please check the logs for required permissions.", e);
            }
            throw new RuntimeException("Failed to initialize Vault client: " + e.getMessage(), e);
        }
    }

    // private void testTokenPermissions() throws Exception {
    //     logger.info("Testing token permissions...");
        
    //     try {
    //         // Test transit engine access by attempting to list keys
    //         vaultTemplate.opsForTransit().getKeys();
    //         logger.info("Transit engine access test successful");
            
    //         // Test secret engine access by attempting to list secrets
    //         vaultTemplate.opsForVersionedKeyValue("secret").list("data/metadata");
    //         logger.info("Secret engine access test successful");
            
    //         logger.info("Token permissions test completed successfully");
    //     } catch (Exception e) {
    //         logger.error("Token permissions test failed: {}", e.getMessage());
    //         logger.error("Required permissions:");
    //         logger.error("1. transit/keys/* - for managing encryption keys");
    //         logger.error("2. transit/encrypt/* - for encryption operations");
    //         logger.error("3. transit/decrypt/* - for decryption operations");
    //         logger.error("4. secret/data/metadata/* - for storing metadata");
    //         throw new RuntimeException("Token lacks required permissions. Please check the logs for required permissions.", e);
    //     }
    // }

    public void initializeTransitKey(EncryptionAlgorithm algorithm, String keyName) throws Exception {
        try {
            String checkUrl = config.getVaultAddress() + "/v1/" + TRANSIT_KEY_PATH + "/" + keyName;
            logger.info("Checking if transit key exists at: {}", checkUrl);
            
            // First check if we have permission to access transit engine
            try {
                HttpHeaders headers = new HttpHeaders();
                headers.set("X-Vault-Token", token);
                HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

                ResponseEntity<String> checkResponse = restTemplate.exchange(
                    checkUrl,
                    HttpMethod.GET,
                    requestEntity,
                    String.class
                );

                if (checkResponse.getStatusCode() == HttpStatus.OK) {
                    logger.info("Transit key already exists: {}", keyName);
                    return;
                }
            } catch (HttpClientErrorException.NotFound e) {
                logger.info("Transit key does not exist, will create: {}", keyName);
            }
            
            String createUrl = config.getVaultAddress() + "/v1/" + TRANSIT_KEY_PATH + "/" + keyName;
            logger.info("Creating transit key at: {}", createUrl);
            
            Map<String, Object> keyConfig = new HashMap<>();
            keyConfig.put("type", algorithm.getVaultType());
            keyConfig.put("derived", true);
            keyConfig.put("allow_plaintext_backup", false);
            keyConfig.put("convergent_encryption", true);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("X-Vault-Token", token);
            
            HttpEntity<Map<String, Object>> request = new HttpEntity<>(keyConfig, headers);
            ResponseEntity<String> response = restTemplate.postForEntity(createUrl, request, String.class);
            
            logger.info("Transit key creation response code: {}", response.getStatusCode());
            logger.info("Transit key creation response body: {}", response.getBody());
            
            if (response.getStatusCode() != HttpStatus.NO_CONTENT && 
                response.getStatusCode() != HttpStatus.OK) {
                throw new RuntimeException("Failed to create transit key: " + response.getBody());
            }
            
        } catch (Exception e) {
            logger.error("Failed to initialize transit key: {}", keyName, e);
            if (e instanceof HttpClientErrorException.Forbidden) {
                throw new RuntimeException("Vault token lacks required permissions. Please check the logs for required permissions.", e);
            }
            throw new RuntimeException("Failed to initialize transit key: " + e.getMessage(), e);
        }
    }

    public EncryptionResult encrypt(String fileId, byte[] data, EncryptionAlgorithm algorithm) throws Exception {
        try {
            String keyName = algorithm instanceof AESGCMAlgorithm ? AES_KEY_NAME : CHACHA_KEY_NAME;
            initializeTransitKey(algorithm, keyName);
            
            String ciphertext = encryptOuter(fileId, data);
            
            EncryptionResult result = new EncryptionResult();
            result.setFileId(fileId);
            result.setCiphertext(ciphertext);
            //result.setAlgorithm(algorithm.getName());
            //result.setKeySize(algorithm.getKeySize());
            //result.setMode(algorithm.getMode());
            //result.setAuthenticated(algorithm.isAuthenticated());
            
            return result;

        } catch (Exception e) {
            logger.error("Encryption failed", e);
            throw new RuntimeException("Encryption failed: " + e.getMessage(), e);
        }
    }

    public byte[] decrypt(String fileId, String ciphertext) throws Exception {
        if (ciphertext == null || ciphertext.trim().isEmpty()) {
            logger.error("Cannot decrypt null or empty ciphertext for file: {}", fileId);
            throw new RuntimeException("Cannot decrypt null or empty ciphertext for file: " + fileId);
        }
        
        logger.info("Decrypting content for file ID: {}, content length: {}", fileId, ciphertext.length());
        
        // Get metadata for key information
        Map<String, Object> metadata = getMetadata(fileId);
        if (metadata == null) {
            logger.error("Metadata not found for file ID: {}", fileId);
            throw new RuntimeException("Metadata not found for file ID: " + fileId);
        }
        
        logger.info("Retrieved metadata for file: {}", fileId);
        
        // Determine key name from metadata
        String keyName = getKeyNameFromMetadata(fileId);
        logger.info("Using key from metadata: {} for file: {}", keyName, fileId);
        
        try {
            // Check if ciphertext is already in Vault format
            if (ciphertext.startsWith("vault:v")) {
                logger.debug("Ciphertext already in Vault format");
                return decryptWithKey(fileId, ciphertext, keyName);
            }
            
            // Check if this might be a raw file in Base64
            if (ciphertext.startsWith("iVBORw0K") || // PNG signature in Base64
                ciphertext.startsWith("/9j/") ||     // JPEG signature in Base64
                ciphertext.startsWith("JVBERi")) {   // PDF signature in Base64
                
                logger.warn("Content appears to be a Base64 encoded raw file, not encrypted data");
                try {
                    // Try returning the decoded content directly
                    return Base64.getDecoder().decode(ciphertext);
                } catch (IllegalArgumentException e) {
                    logger.warn("Failed to decode as raw Base64 file, will attempt decryption");
                }
            }
            
            // Format ciphertext for Vault if needed
            String formattedCiphertext = "vault:v1:" + ciphertext;
            logger.debug("Formatted ciphertext for Vault: {} chars", formattedCiphertext.length());
            
            // Use Vault Transit for decryption
            return decryptWithKey(fileId, formattedCiphertext, keyName);
        } 
        catch (Exception e) {
            logger.error("Failed to decrypt data for file ID: {}", fileId, e);
            logger.warn("Direct decryption failed: {}", e.getMessage());
            
            // Check if ciphertext looks like binary data encoded as text (or a corrupted text conversion of binary)
            boolean looksLikeBinaryData = false;
            int nonAsciiChars = 0;
            for (int i = 0; i < Math.min(100, ciphertext.length()); i++) {
                if ((int)ciphertext.charAt(i) > 127) {
                    nonAsciiChars++;
                }
            }
            
            if (nonAsciiChars > 10) {
                logger.warn("Ciphertext appears to be binary data incorrectly treated as text");
                looksLikeBinaryData = true;
            }
            
            // For binary data treated as text, try alternate approaches
            if (looksLikeBinaryData) {
                logger.info("Trying alternative approach for binary data treated as text");
                
                try {
                    // Try converting back to bytes and encoding properly
                    byte[] rawBytes = ciphertext.getBytes(StandardCharsets.ISO_8859_1); // Use ISO-8859-1 to preserve byte values
                    String properBase64 = Base64.getEncoder().encodeToString(rawBytes);
                    String vaultFormat = "vault:v1:" + properBase64;
                    
                    return decryptWithKey(fileId, vaultFormat, keyName);
                } catch (Exception e2) {
                    logger.error("Alternative approach also failed", e2);
                }
            }
            
            // Never return raw content as fallback - this is a security risk
            throw new RuntimeException("All decryption methods failed for file: " + fileId, e);
        }
    }
    

    public void rotateKey(EncryptionAlgorithm algorithm) throws Exception {
        String keyName = algorithm instanceof AESGCMAlgorithm ? AES_KEY_NAME : CHACHA_KEY_NAME;
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpPost request = new HttpPost(config.getVaultAddress() + "/v1/" + TRANSIT_KEY_PATH + "/keys/" + keyName + "/rotate");
            request.setHeader("X-Vault-Token", token);
            
            try (CloseableHttpResponse response = client.execute(request)) {
                if (response.getCode() != 200) {
                    throw new RuntimeException("Failed to rotate key: " + keyName);
                }
                logger.info("Successfully rotated transit key: {} with algorithm: {}", keyName, algorithm.getName());
                updateMinEncryptionVersion(keyName);
            }
        }
    }

    private void updateMinEncryptionVersion(String keyName) throws Exception {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpPost request = new HttpPost(config.getVaultAddress() + "/v1/" + TRANSIT_KEY_PATH + "/keys/" + keyName + "/config");
            request.setHeader("X-Vault-Token", token);
            
            Map<String, Object> configData = new HashMap<>();
            configData.put("min_encryption_version", 2);
            
            request.setEntity(new StringEntity(objectMapper.writeValueAsString(configData), ContentType.APPLICATION_JSON));
            
            try (CloseableHttpResponse response = client.execute(request)) {
                if (response.getCode() != 200) {
                    throw new RuntimeException("Failed to update min encryption version for key: " + keyName);
                }
                logger.info("Successfully updated min encryption version for key: {}", keyName);
            }
        }
    }

    private void testVaultConnection() throws Exception {
        // Test the connection by reading the config of the AES key.
        String url = config.getVaultAddress() + "/v1/" + TRANSIT_KEY_PATH + "/aes-encryption-key";
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            request.setHeader("X-Vault-Token", token);
            try (CloseableHttpResponse response = client.execute(request)) {
                int statusCode = response.getCode();
                if (statusCode != 200) {
                    throw new RuntimeException("Vault token is invalid or lacks access to transit keys. Response code: " + statusCode);
                }
                logger.info("Vault connection test successful. AES key is accessible.");
            }
        }
    }

    public void authenticateWithAppRole(String roleId, String secretId) throws Exception {
        logger.info("Authenticating with Vault using AppRole");
        logger.info("Role ID: {}", roleId);
        logger.info("Secret ID length: {}", secretId != null ? secretId.length() : 0);
    
        Map<String, String> loginData = new HashMap<>();
        loginData.put("role_id", roleId);
        loginData.put("secret_id", secretId);
    
        String loginJson = objectMapper.writeValueAsString(loginData);
    
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpPost request = new HttpPost(config.getVaultAddress() + "/v1/auth/approle/login");
            request.setEntity(new StringEntity(loginJson, ContentType.APPLICATION_JSON));
    
            try (CloseableHttpResponse response = client.execute(request)) {
                int statusCode = response.getCode();
                String responseBody = EntityUtils.toString(response.getEntity());
    
                if (statusCode != 200) {
                    throw new RuntimeException("Failed to authenticate with Vault. Status: " + statusCode + ", Response: " + responseBody);
                }
    
                Map<String, Object> authResponse = objectMapper.readValue(responseBody, Map.class);
                Map<String, String> auth = (Map<String, String>) authResponse.get("auth");
                this.token = auth.get("client_token");
    
                logger.info("Successfully authenticated with Vault. Token length: {}", token != null ? token.length() : 0);
            }
        }
    }
    
    // AppRole-based secret id generation (TTL is 24h)
    public String generateSecretId() throws Exception {
        String roleId = config.getVaultRoleId();
        logger.info("Generating new Secret ID for role: {}", roleId);
    
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            String url = config.getVaultAddress() + "/v1/auth/approle/role/proxy-role/secret-id";
            HttpPost request = new HttpPost(url);
            logger.info("Vault token print: {}", config.getVaultToken());
            request.setHeader("X-Vault-Token", config.getVaultToken());
    
            try (CloseableHttpResponse response = client.execute(request)) {
                int statusCode = response.getCode();
                String responseBody = EntityUtils.toString(response.getEntity());
                if (statusCode != 200) {
                    throw new RuntimeException("Failed to generate Secret ID. Status: " + statusCode + ", Response: " + responseBody);
                }
    
                Map<String, Object> authResponse = objectMapper.readValue(responseBody, Map.class);
                Map<String, Object> data = (Map<String, Object>) authResponse.get("data");
                return (String) data.get("secret_id");
            }
        }
    }
    
    public void storeMetadata(String fileId, Map<String, Object> metadata) throws Exception {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            // URL encode the fileId to handle spaces and special characters
            String encodedFileId = URLEncoder.encode(fileId, StandardCharsets.UTF_8.name());
            HttpPost request = new HttpPost(config.getVaultAddress() + "/v1/" + METADATA_PATH + "/" + encodedFileId);
            request.setHeader("X-Vault-Token", token);
            
            Map<String, Object> payload = new HashMap<>();
            payload.put("data", metadata);
            
            request.setEntity(new StringEntity(objectMapper.writeValueAsString(payload), ContentType.APPLICATION_JSON));
            
            try (CloseableHttpResponse response = client.execute(request)) {
                if (response.getCode() != 200) {
                    throw new RuntimeException("Failed to store metadata in Vault");
                }
                logger.info("Successfully stored metadata for file ID: {}", fileId);
                
                // Update the cache
                metadataCache.put(fileId, metadata);
                metadataCacheTimestamps.put(fileId, System.currentTimeMillis());
            }
        }
    }

    public Map<String, Object> getMetadata(String fileId) {
        try {
            // Check cache first
            if (metadataCache.containsKey(fileId)) {
                Long timestamp = metadataCacheTimestamps.get(fileId);
                if (timestamp != null && System.currentTimeMillis() - timestamp < CACHE_TTL_MILLIS) {
                    cacheHits.incrementAndGet();
                    logger.debug("Cache hit for metadata of file: {}", fileId);
                    return metadataCache.get(fileId);
                }
            }
            cacheMisses.incrementAndGet();

            // If not in cache or cache expired, retrieve from Vault
            logger.info("Retrieving metadata from Vault for file ID: {}", fileId);
            try (CloseableHttpClient client = HttpClients.createDefault()) {
                String encodedFileId = URLEncoder.encode(fileId, StandardCharsets.UTF_8.name());
                HttpGet request = new HttpGet(config.getVaultAddress() + "/v1/" + METADATA_PATH + "/" + encodedFileId);
                request.setHeader("X-Vault-Token", token);

                try (CloseableHttpResponse response = client.execute(request)) {
                    if (response.getCode() == 404) {
                        logger.warn("Metadata not found for file ID: {}", fileId);
                        return null;
                    }
                    if (response.getCode() != 200) {
                        throw new RuntimeException("Failed to retrieve metadata from Vault");
                    }

                    String responseBody = EntityUtils.toString(response.getEntity());
                    Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
                    Map<String, Object> outerData = (Map<String, Object>) responseMap.get("data");
                    Map<String, Object> metadata = (Map<String, Object>) outerData.get("data");

                    // Update the cache
                    if (metadata != null) {
                        metadataCache.put(fileId, metadata);
                        metadataCacheTimestamps.put(fileId, System.currentTimeMillis());
                        logger.info("Successfully retrieved and cached metadata for file ID: {}", fileId);
                    }

                    return metadata;
                }
            }
        } catch (Exception e) {
            logger.error("Error retrieving metadata for file ID: {}", fileId, e);
            return null;
        }
    }

    private HttpHeaders createHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Vault-Token", token);
        return headers;
    }

    public byte[] decryptWithKey(String fileId, String ciphertext, String keyName) {
        if (ciphertext == null || ciphertext.trim().isEmpty()) {
            logger.error("Cannot decrypt null or empty ciphertext for file: {}", fileId);
            throw new RuntimeException("Cannot decrypt null or empty ciphertext for file: " + fileId);
        }
        
        // Get metadata for key information
        Map<String, Object> metadata = getMetadata(fileId);
        if (metadata == null) {
            logger.error("Metadata not found for file ID: {}", fileId);
            throw new RuntimeException("Metadata not found for file ID: " + fileId);
        }
        
        // Get algorithm from metadata
        String algorithmName = (String) metadata.get("algorithm");
        if (algorithmName == null) {
            logger.error("Algorithm not found in metadata for file: {}", fileId);
            throw new RuntimeException("Algorithm not found in metadata for file: " + fileId);
        }
        
        // Get key name from metadata if not provided
        if (keyName == null) {
            keyName = (String) metadata.get("keyName");
            if (keyName == null) {
                logger.error("Key name not found in metadata for file: {} (algorithm: {})", fileId, algorithmName);
                throw new RuntimeException("Key name not found in metadata for file: " + fileId);
            }
        }
        
        logger.info("Decrypting with key: {} for file: {} (ciphertext length: {})", 
                    keyName, fileId, ciphertext.length());
        
        // Format ciphertext for Vault if needed
        if (!ciphertext.startsWith("vault:v")) {
            try {
                // Try to decode as Base64 first
                Base64.getDecoder().decode(ciphertext);
                ciphertext = "vault:v1:" + ciphertext;
                logger.debug("Formatted ciphertext with Vault prefix");
            } catch (IllegalArgumentException e) {
                // Not valid Base64 - log details to help diagnose
                logger.warn("Ciphertext is not valid Base64 for file: {}. Will try to encode the raw data.", fileId);
                
                // Attempt to treat the ciphertext as raw bytes and encode to Base64
                try {
                    String base64 = Base64.getEncoder().encodeToString(ciphertext.getBytes(StandardCharsets.UTF_8));
                    ciphertext = "vault:v1:" + base64;
                    logger.debug("Encoded raw data to Base64 and added Vault prefix");
                } catch (Exception e2) {
                    logger.error("Failed to process ciphertext for file: {}", fileId, e2);
                    throw new RuntimeException("Cannot format ciphertext for decryption", e2);
                }
            }
        }
        
        // Validate final ciphertext format
        if (!ciphertext.matches("^vault:v\\d+:[A-Za-z0-9+/=]+$")) {
            logger.error("Ciphertext format is invalid after processing: {}", 
                ciphertext.substring(0, Math.min(50, ciphertext.length())));
            throw new RuntimeException("Invalid Vault ciphertext format");
        }
        
        try {
            // Use Vault Transit to decrypt
            try (CloseableHttpClient client = HttpClients.createDefault()) {
                String url = config.getVaultAddress() + "/v1/" + TRANSIT_DECRYPT_PATH + "/" + keyName;
                logger.info("Making decryption request to Vault URL: {}", url);
                
                HttpPost decryptRequest = new HttpPost(url);
                decryptRequest.setHeader("X-Vault-Token", token);
                decryptRequest.setHeader("Content-Type", "application/json");
                
                // Create the request body
                Map<String, String> requestBody = new HashMap<>();
                requestBody.put("ciphertext", ciphertext);
                
                // Add context for authenticated encryption
                // if (algorithmName.contains("GCM") || algorithmName.contains("Poly1305")) {
                //     requestBody.put("context", Base64.getEncoder().encodeToString(fileId.getBytes(StandardCharsets.UTF_8)));
                // }
                
                decryptRequest.setEntity(new StringEntity(objectMapper.writeValueAsString(requestBody), ContentType.APPLICATION_JSON));
                
                try (CloseableHttpResponse response = client.execute(decryptRequest)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    if (response.getCode() != 200) {
                        logger.error("Vault decryption failed with status: {} and response: {}", 
                            response.getCode(), responseBody);
                        throw new RuntimeException("Vault decryption failed with status: " + response.getCode());
                    }
                    
                    Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
                    Map<String, String> responseData = (Map<String, String>) responseMap.get("data");
                    
                    if (responseData == null) {
                        logger.error("Invalid Vault response format - missing 'data' field: {}", responseBody);
                        throw new RuntimeException("Invalid Vault response format - missing 'data' field");
                    }
                    
                    String plaintext = responseData.get("plaintext");
                    
                    if (plaintext == null) {
                        logger.error("No plaintext in Vault response: {}", responseBody);
                        throw new RuntimeException("No plaintext in Vault response");
                    }
                    
                    // Decode the base64 plaintext to get the original data
                    return Base64.getDecoder().decode(plaintext);
                }
            }
        } catch (Exception e) {
            logger.error("Failed to decrypt data for file ID: {}", fileId, e);
            throw new RuntimeException("Failed to decrypt data for file ID: " + fileId, e);
        }
    }
    
    public String encryptOuter(String fileId, byte[] data) throws Exception {
        // Initialize the outer encryption key if it doesn't exist
        try {
            initializeTransitKey(new AESGCMAlgorithm(), OUTER_ENCRYPTION_KEY);
            logger.info("Outer encryption key initialized successfully");
        } catch (Exception e) {
            logger.error("Failed to initialize outer encryption key: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to initialize outer encryption key: " + e.getMessage(), e);
        }
        
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            String url = config.getVaultAddress() + "/v1/" + TRANSIT_ENCRYPT_PATH + "/" + OUTER_ENCRYPTION_KEY;
            logger.info("Making encryption request to Vault URL: {}", url);
            
            HttpPost encryptRequest = new HttpPost(url);
            encryptRequest.setHeader("X-Vault-Token", token);
            
            Map<String, Object> encryptData = new HashMap<>();
            String plaintext = Base64.getEncoder().encodeToString(data);
            encryptData.put("plaintext", plaintext);
            
            // Add context for key derivation
            String context = Base64.getEncoder().encodeToString(fileId.getBytes(StandardCharsets.UTF_8));
            encryptData.put("context", context);
            
            String requestBody = objectMapper.writeValueAsString(encryptData);
            //logger.debug("Encryption request body: {}", requestBody);
            
            encryptRequest.setEntity(new StringEntity(requestBody, ContentType.APPLICATION_JSON));
            
            try (CloseableHttpResponse response = client.execute(encryptRequest)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                logger.info("Outer encryption response code: {}", response.getCode());
                logger.debug("Outer encryption response body: {}", responseBody);
                
                if (response.getCode() != 200) {
                    logger.error("Failed to encrypt outer layer. Response code: {}, Body: {}", 
                        response.getCode(), responseBody);
                    throw new RuntimeException("Failed to encrypt outer layer. Response code: " + 
                        response.getCode() + ", Body: " + responseBody);
                }
                
                Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
                Map<String, String> responseData = (Map<String, String>) responseMap.get("data");
                String ciphertext = responseData.get("ciphertext");
                
                if (ciphertext == null) {
                    logger.error("No ciphertext in response: {}", responseBody);
                    throw new RuntimeException("No ciphertext in response");
                }
                
                // Ensure the ciphertext has the Vault prefix
                if (!ciphertext.startsWith("vault:v")) {
                    logger.error("Generated ciphertext missing Vault prefix: {}", 
                        ciphertext.substring(0, Math.min(50, ciphertext.length())));
                    throw new RuntimeException("Generated ciphertext missing Vault prefix");
                }
                
                logger.info("Successfully encrypted outer layer for file ID: {}", fileId);
                return ciphertext;
            }
        } catch (Exception e) {
            logger.error("Error in encryptOuter for file ID {}: {}", fileId, e.getMessage(), e);
            throw new RuntimeException("Failed to encrypt outer layer: " + e.getMessage(), e);
        }
    }

    public String decryptOuter(String fileId, String ciphertext) throws Exception {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            String url = config.getVaultAddress() + "/v1/" + TRANSIT_DECRYPT_PATH + "/" + OUTER_ENCRYPTION_KEY;
            logger.info("Making outer decryption request to: {}", url);
            
            HttpPost decryptRequest = new HttpPost(url);
            decryptRequest.setHeader("X-Vault-Token", token);

            Map<String, Object> decryptData = new HashMap<>();
            decryptData.put("ciphertext", ciphertext);
            String context = Base64.getEncoder().encodeToString(fileId.getBytes(StandardCharsets.UTF_8));
            decryptData.put("context", context);

            String requestBody = objectMapper.writeValueAsString(decryptData);
            //logger.debug("Outer decryption request body: {}", requestBody);
            
            decryptRequest.setEntity(new StringEntity(requestBody, ContentType.APPLICATION_JSON));

            try (CloseableHttpResponse response = client.execute(decryptRequest)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                if (response.getCode() != 200) {
                    logger.error("Outer decryption failed. Code: {}, Response: {}", response.getCode(), responseBody);
                    throw new RuntimeException("Failed to decrypt outer layer: " + responseBody);
                }

                Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
                Map<String, String> responseData = (Map<String, String>) responseMap.get("data");
                String plaintext = responseData.get("plaintext");
                
                if (plaintext == null) {
                    logger.error("No plaintext in response: {}", responseBody);
                    throw new RuntimeException("No plaintext in response");
                }
                
                // Decode the base64 plaintext and return it directly
                byte[] decodedBytes = Base64.getDecoder().decode(plaintext);
                String result = new String(decodedBytes, StandardCharsets.UTF_8);
                logger.info("Outer decryption successful. Result length: {}", result.length());
                return result;
            }
        }
    }
    
    public long getTokenTTL() throws Exception {
        String url = config.getVaultAddress() + "/v1/auth/token/lookup-self";
        HttpGet request = new HttpGet(url);
        request.setHeader("X-Vault-Token", token);

        try (CloseableHttpClient httpClient = HttpClients.createDefault();
             CloseableHttpResponse response = httpClient.execute(request)) {
            
            String responseBody = EntityUtils.toString(response.getEntity());
            
            if (response.getCode() == 200) {
                JSONObject jsonResponse = new JSONObject(responseBody);
                JSONObject data = jsonResponse.getJSONObject("data");
                return data.getLong("ttl");
            } else {
                throw new Exception("Failed to get token TTL: " + responseBody);
            }
        }
    }

    public byte[] encryptWithKey(String fileId, EncryptionAlgorithm algorithm, byte[] data) {
        try {
            String algorithmName = algorithm.getName();
            String keyName = algorithmName.toLowerCase().contains("chacha") ? CHACHA_KEY_NAME : AES_KEY_NAME;
            
            // Use Vault Transit to encrypt
            try (CloseableHttpClient client = HttpClients.createDefault()) {
                String url = config.getVaultAddress() + "/v1/" + TRANSIT_ENCRYPT_PATH + "/" + keyName;
                logger.info("Making encryption request to Vault URL: {}", url);
                
                HttpPost encryptRequest = new HttpPost(url);
                encryptRequest.setHeader("X-Vault-Token", token);
                encryptRequest.setHeader("Content-Type", "application/json");
                
                // Create the request body
                Map<String, String> requestBody = new HashMap<>();
                requestBody.put("plaintext", Base64.getEncoder().encodeToString(data));
                
                // Add context for authenticated encryption
                // if (algorithm.isAuthenticated()) {
                //     requestBody.put("context", Base64.getEncoder().encodeToString(fileId.getBytes(StandardCharsets.UTF_8)));
                // }
                
                encryptRequest.setEntity(new StringEntity(objectMapper.writeValueAsString(requestBody), ContentType.APPLICATION_JSON));
                
                try (CloseableHttpResponse response = client.execute(encryptRequest)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    if (response.getCode() != 200) {
                        logger.error("Vault encryption failed with status: {} and response: {}", 
                            response.getCode(), responseBody);
                        throw new RuntimeException("Vault encryption failed with status: " + response.getCode());
                    }
                    
                    Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
                    Map<String, String> responseData = (Map<String, String>) responseMap.get("data");
                    
                    if (responseData == null) {
                        logger.error("Invalid Vault response format - missing 'data' field: {}", responseBody);
                        throw new RuntimeException("Invalid Vault response format - missing 'data' field");
                    }
                    
                    String ciphertext = responseData.get("ciphertext");
                    
                    if (ciphertext == null) {
                        logger.error("No ciphertext in Vault response: {}", responseBody);
                        throw new RuntimeException("No ciphertext in Vault response");
                    }
                    
                    // Verify the ciphertext format
                    if (!ciphertext.matches("^vault:v\\d+:[A-Za-z0-9+/=]+$")) {
                        logger.error("Invalid ciphertext format from Vault: {}", ciphertext);
                        throw new RuntimeException("Invalid ciphertext format from Vault");
                    }
                    
                    // Store the ciphertext format in metadata
                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("keyName", keyName);
                    metadata.put("algorithm", algorithmName);
                    metadata.put("ciphertextFormat", "vault:v1");
                    storeMetadata(fileId, metadata);
                    
                    return ciphertext.getBytes(StandardCharsets.UTF_8);
                }
            }
        } catch (Exception e) {
            logger.error("Failed to encrypt data for file ID: {}", fileId, e);
            throw new RuntimeException("Failed to encrypt data for file ID: " + fileId, e);
        }
    }

    /**
     * Invalidates the key cache if a key has been rotated or policies changed
     */
    public void invalidateKeyCache(String keyName) {
        if (keyName == null) {
            transitKeyCache.clear();
            transitKeyCacheTimestamps.clear();
            logger.info("Cleared entire transit key cache");
        } else {
            transitKeyCache.remove(keyName);
            transitKeyCacheTimestamps.remove(keyName);
            logger.info("Removed {} from transit key cache", keyName);
        }
    }
    
    /**
     * Gets cache statistics
     * @return Map with cache statistics
     */
    public Map<String, Object> getCacheStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("cacheHits", cacheHits.get());
        stats.put("cacheMisses", cacheMisses.get());
        stats.put("hitRatio", cacheHits.get() + cacheMisses.get() > 0 ? 
            (double) cacheHits.get() / (cacheHits.get() + cacheMisses.get()) : 0);
        stats.put("transitKeyCacheSize", transitKeyCache.size());
        stats.put("metadataCacheSize", metadataCache.size());
        stats.put("cacheTTLSeconds", TimeUnit.MILLISECONDS.toSeconds(CACHE_TTL_MILLIS));
        return stats;
    }
    
    /**
     * Clears all caches
     */
    public void clearAllCaches() {
        transitKeyCache.clear();
        transitKeyCacheTimestamps.clear();
        metadataCache.clear();
        metadataCacheTimestamps.clear();
        logger.info("Cleared all VaultService caches");
    }

   

    public byte[] decryptBinary(String fileId, byte[] encryptedData, String algorithmName) {
        try {
            // Validate input
            if (encryptedData == null || encryptedData.length == 0) {
                logger.error("Cannot decrypt null or empty binary data for file: {}", fileId);
                throw new RuntimeException("Cannot decrypt null or empty binary data");
            }
            
            logger.info("Attempting to decrypt binary data for file: {} (size: {} bytes)", 
                       fileId, encryptedData.length);
            
            // Check if the data might actually be non-encrypted
            if (encryptedData.length < 20) {
                logger.warn("Binary data for file: {} is suspiciously small ({} bytes), may not be encrypted", 
                           fileId, encryptedData.length);
            }
            
            // Try to detect common file signatures that would indicate non-encrypted data
            boolean seemsToBeRawFile = false;
            
            // Check for common file signatures
            if (encryptedData.length >= 4) {
                // PNG signature
                if (encryptedData[0] == (byte)0x89 && encryptedData[1] == (byte)0x50 && 
                    encryptedData[2] == (byte)0x4E && encryptedData[3] == (byte)0x47) {
                    logger.warn("Binary data for file: {} appears to be a raw PNG file (not encrypted)", fileId);
                    seemsToBeRawFile = true;
                }
                // JPEG signature
                else if (encryptedData[0] == (byte)0xFF && encryptedData[1] == (byte)0xD8 && 
                         encryptedData[2] == (byte)0xFF) {
                    logger.warn("Binary data for file: {} appears to be a raw JPEG file (not encrypted)", fileId);
                    seemsToBeRawFile = true;
                }
                // PDF signature
                else if (encryptedData[0] == (byte)0x25 && encryptedData[1] == (byte)0x50 && 
                         encryptedData[2] == (byte)0x44 && encryptedData[3] == (byte)0x46) {
                    logger.warn("Binary data for file: {} appears to be a raw PDF file (not encrypted)", fileId);
                    seemsToBeRawFile = true;
                }
            }
            
            if (seemsToBeRawFile) {
                logger.error("Cannot decrypt data that appears to be a raw file (not encrypted)");
                throw new RuntimeException("Data appears to be a raw file, not encrypted content");
            }
            
            // Get key name from metadata
            String keyName = getKeyNameFromMetadata(fileId);
            logger.info("Using key name from metadata for binary decryption: {}", keyName);
            
            // Format ciphertext properly for Vault Transit
            try {
                String base64Ciphertext = Base64.getEncoder().encodeToString(encryptedData);
                
                // Vault expects format: vault:v1:<base64data>
                String formattedCiphertext = "vault:v1:" + base64Ciphertext;
                logger.debug("Formatted ciphertext for Vault Transit (length: {})", formattedCiphertext.length());
                
                return decryptWithKey(fileId, formattedCiphertext, keyName);
            } catch (Exception e) {
                logger.error("Failed to process binary data for decryption: {}", e.getMessage());
                throw new RuntimeException("Failed to process binary data for decryption", e);
            }
        } catch (Exception e) {
            logger.error("Failed to decrypt binary data for file: {}", fileId, e);
            throw new RuntimeException("Failed to decrypt binary data for file: " + fileId, e);
        }
    }

    public Map<String, Object> retrieveMetadata(String fileId) throws Exception {
        // Check cache first
        if (metadataCache.containsKey(fileId)) {
            long timestamp = metadataCacheTimestamps.get(fileId);
            if (System.currentTimeMillis() - timestamp < CACHE_TTL_MILLIS) {
                logger.debug("Retrieved metadata from cache for file ID: {}", fileId);
                return metadataCache.get(fileId);
            }
        }

        try (CloseableHttpClient client = HttpClients.createDefault()) {
            // URL encode the fileId to handle spaces and special characters
            String encodedFileId = URLEncoder.encode(fileId, StandardCharsets.UTF_8.name());
            HttpGet request = new HttpGet(config.getVaultAddress() + "/v1/" + METADATA_PATH + "/" + encodedFileId);
            request.setHeader("X-Vault-Token", token);
            
            try (CloseableHttpResponse response = client.execute(request)) {
                if (response.getCode() == 404) {
                    logger.warn("Metadata not found for file ID: {}", fileId);
                    return null;
                }
                if (response.getCode() != 200) {
                    throw new RuntimeException("Failed to retrieve metadata from Vault");
                }
                
                String responseBody = EntityUtils.toString(response.getEntity());
                Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
                Map<String, Object> outerData = (Map<String, Object>) responseMap.get("data");
                Map<String, Object> metadata = (Map<String, Object>) outerData.get("data");
                
                // Update the cache
                metadataCache.put(fileId, metadata);
                metadataCacheTimestamps.put(fileId, System.currentTimeMillis());
                
                logger.info("Successfully retrieved metadata for file ID: {}", fileId);
                return metadata;
            }
        }
    }

    private String cleanCiphertext(String ciphertext) {
        if (ciphertext == null) {
            return null;
        }
        
        // Remove any whitespace
        ciphertext = ciphertext.trim();
        
        // If it already has the Vault prefix, return as is
        if (ciphertext.startsWith("vault:v")) {
            return ciphertext;
        }
        
        // If it's base64 encoded but missing the prefix, add it
        try {
            Base64.getDecoder().decode(ciphertext);
            return "vault:v1:" + ciphertext;
        } catch (IllegalArgumentException e) {
            // Not valid base64, return original
            return ciphertext;
        }
    }

    private String extractVaultCiphertext(String content) {
        if (content == null) {
            return null;
        }
        
        // Remove any whitespace
        content = content.trim();
        
        // If it already has the Vault prefix, return as is
        if (content.startsWith("vault:v")) {
            return content;
        }
        
        // Try to find the Vault prefix in the content
        int prefixIndex = content.indexOf("vault:v");
        if (prefixIndex >= 0) {
            return content.substring(prefixIndex);
        }
        
        // If no prefix found, try to decode as base64
        try {
            Base64.getDecoder().decode(content);
            return "vault:v1:" + content;
        } catch (IllegalArgumentException e) {
            // Not valid base64, return original
            return content;
        }
    }

    private String cleanCiphertextFormat(String ciphertext) {
        if (ciphertext == null || ciphertext.trim().isEmpty()) {
            return ciphertext;
        }
        
        // Remove any whitespace
        ciphertext = ciphertext.trim();
        
        // Check if it already has the correct format
        if (ciphertext.matches("^vault:v\\d+:[A-Za-z0-9+/=]+$")) {
            return ciphertext;
        }
        
        // If it starts with vault:v but has incorrect format
        if (ciphertext.startsWith("vault:v")) {
            // Extract version number and base64 portion
            String[] parts = ciphertext.split(":", 3);
            if (parts.length == 3) {
                // Clean up version number (remove any non-digit characters)
                String version = parts[1].replaceAll("[^0-9]", "");
                // Reconstruct with proper format
                return "vault:v" + version + ":" + parts[2];
            }
        }
        
        // If it's just base64 encoded data, wrap it in vault format
        try {
            Base64.getDecoder().decode(ciphertext);
            return "vault:v1:" + ciphertext;
        } catch (IllegalArgumentException e) {
            // Not valid base64, return as is
            return ciphertext;
        }
    }

    private String extractVaultFormattedCiphertext(String ciphertext) {
        if (ciphertext == null || ciphertext.trim().isEmpty()) {
            return ciphertext;
        }
        
        // Remove any whitespace
        ciphertext = ciphertext.trim();
        
        // If it already has the correct format, return as is
        if (ciphertext.matches("^vault:v\\d+:[A-Za-z0-9+/=]+$")) {
            return ciphertext;
        }
        
        // If it starts with vault:v, extract the formatted portion
        if (ciphertext.startsWith("vault:v")) {
            // Find the last colon that separates the base64 portion
            int lastColon = ciphertext.lastIndexOf(':');
            if (lastColon > 0) {
                return ciphertext.substring(0, lastColon + 1) + 
                       ciphertext.substring(lastColon + 1).replaceAll("[^A-Za-z0-9+/=]", "");
            }
        }
        
        return ciphertext;
    }

    public String getKeyNameFromMetadata(String fileId) {
        Map<String, Object> metadata = getMetadata(fileId);
        if (metadata == null) throw new RuntimeException("No metadata for file: " + fileId);
        
        // Check for explicit keyName field
        String keyName = (String) metadata.get("keyName");
        if (keyName != null) {
            logger.info("Found explicit keyName in metadata: {}", keyName);
            return keyName;
        }
        
        // If no explicit keyName, determine it from the algorithm
        String algorithm = (String) metadata.get("algorithm");
        if (algorithm == null) {
            logger.warn("No algorithm in metadata, defaulting to AES-GCM");
            return AES_KEY_NAME;
        }
        
        logger.info("Determining key name from algorithm: {}", algorithm);
        if (algorithm.toLowerCase().contains("chacha") || algorithm.toLowerCase().contains("poly1305")) {
            return CHACHA_KEY_NAME;
        } else {
            return AES_KEY_NAME;
        }
    }
}
