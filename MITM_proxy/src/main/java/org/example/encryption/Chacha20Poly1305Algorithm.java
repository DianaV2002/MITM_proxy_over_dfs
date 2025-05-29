package org.example.encryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Arrays;

public class Chacha20Poly1305Algorithm implements EncryptionAlgorithm {
    private static final int KEY_LENGTH = 32; // 256 bits
    private static final String MODE = "Poly1305";
    private static final double PERFORMANCE_SCORE = 0.95;  // Higher performance score for Chacha20
    private static final double SECURITY_SCORE = 0.9;
    private static final int NONCE_LENGTH = 12; // 96 bits
    private static final int TAG_LENGTH = 128; // 128 bits
    private static final long LARGE_FILE_THRESHOLD = 1024 * 1024; // 1MB
    private static final Logger logger = LoggerFactory.getLogger(Chacha20Poly1305Algorithm.class);

    @Override
    public String getName() {
        return "Chacha20-Poly1305";
    }

    @Override
    public int getKeySize() {
        return KEY_LENGTH;
    }

    @Override
    public String getMode() {
        return MODE;
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }

    @Override
    public boolean supportsKeyDerivation() {
        return true;
    }

    @Override
    public double getPerformanceScore() {
        return PERFORMANCE_SCORE;
    }

    @Override
    public double getSecurityScore() {
        return SECURITY_SCORE;
    }

    @Override
    public boolean isSuitableForFile(long fileSize, boolean isSensitive) {
        // Chacha20 is particularly good for large files
        return fileSize > LARGE_FILE_THRESHOLD;
    }

    @Override
    public String getVaultType() {
        return "chacha20-poly1305";
    }

    @Override
    public byte[] encrypt(byte[] data, int offset, int length, byte[] key) {
        try {
            if (key.length != KEY_LENGTH) {
                throw new IllegalArgumentException("Key length must be " + KEY_LENGTH + " bytes (256 bits)");
            }

            // Generate a random nonce
            byte[] nonce = new byte[NONCE_LENGTH];
            new SecureRandom().nextBytes(nonce);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            SecretKey secretKey = new SecretKeySpec(key, "ChaCha20");
            IvParameterSpec ivSpec = new IvParameterSpec(nonce);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            // Encrypt the data
            byte[] encrypted = cipher.doFinal(data, offset, length);

            // Combine nonce and ciphertext (which includes the tag)
            byte[] result = new byte[NONCE_LENGTH + encrypted.length];
            System.arraycopy(nonce, 0, result, 0, NONCE_LENGTH);
            System.arraycopy(encrypted, 0, result, NONCE_LENGTH, encrypted.length);

            logger.debug("Encrypted {} bytes with ChaCha20-Poly1305 (nonce: {} bytes, tag: {} bits)", 
                length, NONCE_LENGTH, TAG_LENGTH);
            return result;
        } catch (Exception e) {
            logger.error("Encryption failed: {}", e.getMessage());
            throw new RuntimeException("ChaCha20-Poly1305 encryption failed", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] key) {
        try {
            if (key.length != KEY_LENGTH) {
                throw new IllegalArgumentException("Key length must be " + KEY_LENGTH + " bytes (256 bits)");
            }

            if (encryptedData.length < NONCE_LENGTH + TAG_LENGTH / 8) {
                throw new IllegalArgumentException("Encrypted data too short");
            }

            // Extract nonce and ciphertext (which includes the tag)
            byte[] nonce = Arrays.copyOfRange(encryptedData, 0, NONCE_LENGTH);
            byte[] ciphertextWithTag = Arrays.copyOfRange(encryptedData, NONCE_LENGTH, encryptedData.length);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            SecretKey secretKey = new SecretKeySpec(key, "ChaCha20");
            IvParameterSpec ivSpec = new IvParameterSpec(nonce);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            // Decrypt the data (this will verify the tag)
            byte[] decrypted = cipher.doFinal(ciphertextWithTag);

            logger.debug("Decrypted {} bytes with ChaCha20-Poly1305", decrypted.length);
            return decrypted;
        } catch (Exception e) {
            logger.error("Decryption failed: {}", e.getMessage());
            throw new RuntimeException("ChaCha20-Poly1305 decryption failed", e);
        }
    }
} 