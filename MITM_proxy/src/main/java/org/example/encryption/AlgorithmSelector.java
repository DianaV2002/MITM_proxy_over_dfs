package org.example.encryption;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

public class AlgorithmSelector {
    private static final List<EncryptionAlgorithm> algorithms = new ArrayList<>();
    private static final long LARGE_FILE_THRESHOLD = 1024 * 1024; // 1MB
    
    // Weight constants for the scoring model
    private static final double PERFORMANCE_WEIGHT = 0.2;
    private static final double SECURITY_WEIGHT = 0.2;
    private static final double SENSITIVITY_WEIGHT = 0.2;
    private static final double SIZE_WEIGHT = 0.4;
    
    static {
        algorithms.add(new AESGCMAlgorithm());
        algorithms.add(new Chacha20Poly1305Algorithm());
    }
    
    public static class FileProperties {
        private final long fileSize;
        private final boolean isSensitive;
        private final long accessCount;
        private final boolean isHighValue;
        
        public FileProperties(long fileSize, boolean isSensitive, long accessCount, 
                        boolean isHighValue) {
            this.fileSize = fileSize;
            this.isSensitive = isSensitive;
            this.accessCount = accessCount;
            this.isHighValue = isHighValue;
        }
        
        public long getFileSize() { return fileSize; }
        public boolean isSensitive() { return isSensitive; }
        public long getAccessCount() { return accessCount; }
        public boolean isHighValue() { return isHighValue; }
    }
    
    public static EncryptionAlgorithm selectAlgorithm(FileProperties properties) {
        // Calculate scores for each algorithm
        Map<EncryptionAlgorithm, Double> scores = new HashMap<>();
        for (EncryptionAlgorithm algorithm : algorithms) {
            scores.put(algorithm, calculateAlgorithmScore(algorithm, properties));
        }
        
        // Select algorithm with highest score
        EncryptionAlgorithm selectedAlgorithm = null;
        double maxScore = Double.MIN_VALUE;
        
        for (Map.Entry<EncryptionAlgorithm, Double> entry : scores.entrySet()) {
            if (entry.getValue() > maxScore) {
                maxScore = entry.getValue();
                selectedAlgorithm = entry.getKey();
            }
        }
        
        return selectedAlgorithm != null ? selectedAlgorithm : new AESGCMAlgorithm();
    }
    
    private static double calculateAlgorithmScore(EncryptionAlgorithm algorithm, FileProperties properties) {
        // Calculate base performance and security scores
        double performanceScore = algorithm.getPerformanceScore();
        double securityScore = algorithm.getSecurityScore();
        
        // Calculate size score (continuous value based on file size)
        double sizeScore = calculateSizeScore(properties.getFileSize());
        
        // Calculate sensitivity score (continuous value based on multiple factors)
        double sensitivityScore = calculateSensitivityScore(properties);
        
        // Calculate final score using weighted sum
        double finalScore = (performanceScore * PERFORMANCE_WEIGHT) +
                          (securityScore * SECURITY_WEIGHT) +
                          (sensitivityScore * SENSITIVITY_WEIGHT) +
                          (sizeScore * SIZE_WEIGHT);
        
        // Normalize score to [0, 1] range
        return Math.min(Math.max(finalScore, 0.0), 1.0);
    }
    
    private static double calculateSizeScore(long fileSize) {
        // Use logarithmic scaling for size score
        if (fileSize <= 1024) { // <= 1KB
            return 1.0;
        }
        
        // Calculate score using logarithmic scale
        double logSize = Math.log10(fileSize / 1024.0); // Convert to KB and take log
        double maxLogSize = Math.log10(1024 * 1024 * 1024 / 1024.0); // 1GB in KB
        
        // Normalize to [0, 1] range, with smaller files getting higher scores
        return 1.0 - (logSize / maxLogSize);
    }
    
    private static double calculateSensitivityScore(FileProperties properties) {
        double score = 0.0;
        
        // Base sensitivity from flag
        if (properties.isSensitive()) {
            score += 0.6;
        }
        
        // High value factor
        if (properties.isHighValue()) {
            score += 0.4;
        }
        
        // Access count factor (more accesses = higher sensitivity)
        long accessCount = properties.getAccessCount();
        if (accessCount > 1000) {
            score += 0.3;
        } else if (accessCount > 100) {
            score += 0.2;
        } else if (accessCount > 10) {
            score += 0.1;
        }
        
        return Math.min(score, 1.0);
    }
    
    /**
     * Get an encryption algorithm by its name
     * @param name The name of the algorithm
     * @return The encryption algorithm
     */
    public static EncryptionAlgorithm getAlgorithmByName(String name) {
        for (EncryptionAlgorithm algorithm : algorithms) {
            if (algorithm.getName().equalsIgnoreCase(name)) {
                return algorithm;
            }
        }
        // Default to AES-GCM if not found
        return new AESGCMAlgorithm();
    }
} 