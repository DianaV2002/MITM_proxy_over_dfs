package org.example.encryption;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Arrays;
import java.util.Base64;

public class AESGCMAlgorithm implements EncryptionAlgorithm {
    private static final Logger logger = LoggerFactory.getLogger(AESGCMAlgorithm.class);
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int KEY_LENGTH = 16; // 128 bits
    private static final int IV_LENGTH = 12; // 96 bits
    private static final int TAG_LENGTH = 128; // 128 bits
    private static final double PERFORMANCE_SCORE = 0.9;
    private static final double SECURITY_SCORE = 0.95;

    @Override
    public String getName() {
        return "AES-GCM";
    }

    @Override
    public int getKeySize() {
        return KEY_LENGTH * 8; // 128 bits
    }

    @Override
    public String getMode() {
        return "GCM";
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
        // AES-GCM is suitable for all files, but particularly good for sensitive data
        return true;
    }

    @Override
    public String getVaultType() {
        return "aes-gcm";
    }

    @Override
    public byte[] encrypt(byte[] data, int offset, int length, byte[] key) {
        try {
            if (key.length != KEY_LENGTH) {
                throw new IllegalArgumentException("Key length must be " + KEY_LENGTH + " bytes (128 bits)");
            }

            // Generate a random IV
            byte[] iv = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            // Initialize cipher with explicit tag length
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            // Encrypt the data
            byte[] encrypted = cipher.doFinal(data, offset, length);

            // The encrypted data includes the tag at the end
            // Combine IV and ciphertext (which includes the tag)
            byte[] result = new byte[IV_LENGTH + encrypted.length];
            System.arraycopy(iv, 0, result, 0, IV_LENGTH);
            System.arraycopy(encrypted, 0, result, IV_LENGTH, encrypted.length);

            logger.debug("Encrypted {} bytes with AES-GCM (IV: {} bytes, tag: {} bits)", 
                length, IV_LENGTH, TAG_LENGTH);
            return result;
        } catch (Exception e) {
            logger.error("Encryption failed: {}", e.getMessage());
            throw new RuntimeException("AES-GCM encryption failed", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] key) {
        try {
            if (key.length != KEY_LENGTH) {
                throw new IllegalArgumentException("Key length must be " + KEY_LENGTH + " bytes (128 bits)");
            }

            // Minimum length check: IV (12 bytes) + at least 1 byte of ciphertext + tag (16 bytes)
            if (encryptedData.length < IV_LENGTH + 1 + TAG_LENGTH / 8) {
                throw new IllegalArgumentException("Encrypted data too short for AES-GCM (expected at least " + 
                    (IV_LENGTH + 1 + TAG_LENGTH / 8) + " bytes)");
            }

            // Extract IV and ciphertext (which includes the tag)
            byte[] iv = Arrays.copyOfRange(encryptedData, 0, IV_LENGTH);
            byte[] ciphertextWithTag = Arrays.copyOfRange(encryptedData, IV_LENGTH, encryptedData.length);

            // Initialize cipher with explicit tag length
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            // Decrypt the data (this will verify the tag)
            byte[] decrypted = cipher.doFinal(ciphertextWithTag);

            logger.debug("Decrypted {} bytes with AES-GCM (IV: {} bytes, tag: {} bits)", 
                decrypted.length, IV_LENGTH, TAG_LENGTH);
            return decrypted;
        } catch (Exception e) {
            logger.error("Decryption failed: {}", e.getMessage());
            throw new RuntimeException("AES-GCM decryption failed", e);
        }
    }
} 