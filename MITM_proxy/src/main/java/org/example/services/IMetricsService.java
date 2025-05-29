package org.example.services;

import org.example.model.StorageType;
import org.example.model.StorageMetrics;
import java.util.Map;

public interface IMetricsService {
    void recordOperation(StorageType type, boolean success, long bytesTransferred);
    void updateMetrics(StorageType type, StorageMetrics metrics);
    void updateMetrics(Map<String, Object> metrics);
    Map<String, Object> getPerformanceMetrics();
    Map<StorageType, Double> getThroughput();
    
    // Additional methods for encryption metrics
    void setCurrentFile(String fileName);
    void clearCurrentFile();
    void recordEncryptionOperation(String algorithm, long bytesProcessed, long timeMs);
    void recordDecryptionOperation(String algorithm, long bytesProcessed, long timeMs);
    void handleEncryptionFailure(String fileName, Exception e);
    void clearMetrics();
    void recordBasicIOOperation(int bytesRead, int bytesWritten, long timeMs);
} 