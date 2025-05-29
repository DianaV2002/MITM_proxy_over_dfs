package org.example.encryption;

public interface EncryptionAlgorithm {
    String getName();
    int getKeySize();
    String getMode();
    boolean isAuthenticated();
    boolean supportsKeyDerivation();
    double getPerformanceScore();
    double getSecurityScore();
    boolean isSuitableForFile(long fileSize, boolean isSensitive);
    String getVaultType();
    
    /**
     * Encrypts data with a local key
     * @param data The data to encrypt
     * @param offset The offset in the data
     * @param length The length of data to encrypt
     * @param key The encryption key
     * @return The encrypted data
     */
    byte[] encrypt(byte[] data, int offset, int length, byte[] key);
    
    /**
     * Decrypts data with a local key
     * @param encryptedData The encrypted data
     * @param key The encryption key
     * @return The decrypted data
     */
    byte[] decrypt(byte[] encryptedData, byte[] key);
} 