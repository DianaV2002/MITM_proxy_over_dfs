package org.example.entities;

import org.example.services.VaultService;
import org.example.encryption.EncryptionAlgorithm;

public class EncryptionResult {
    private String fileId;
    private String ciphertext;
    private String algorithm;
    private int keySize;
    private String mode;
    private boolean authenticated;
    
    public EncryptionResult() {}
    
    public String getFileId() {
        return fileId;
    }
    
    public void setFileId(String fileId) {
        this.fileId = fileId;
    }
    
    public String getCiphertext() {
        return ciphertext;
    }
    
    public void setCiphertext(String ciphertext) {
        this.ciphertext = ciphertext;
    }
    
    public String getAlgorithm() {
        return algorithm;
    }
    
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
    
    public int getKeySize() {
        return keySize;
    }
    
    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }
    
    public String getMode() {
        return mode;
    }
    
    public void setMode(String mode) {
        this.mode = mode;
    }
    
    public boolean isAuthenticated() {
        return authenticated;
    }
    
    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }
} 