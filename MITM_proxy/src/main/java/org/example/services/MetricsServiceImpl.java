package org.example.services;

import org.example.model.StorageType;
import org.example.model.StorageMetrics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.List;
import java.util.ArrayList;

@Service
public class MetricsServiceImpl implements IMetricsService {
    private static final Logger logger = LoggerFactory.getLogger(MetricsServiceImpl.class);
    private static final int MAX_HISTORY_SIZE = 100;
    
    // Storage metrics
    private final Map<StorageType, StorageMetrics> currentMetrics = new ConcurrentHashMap<>();
    private final Map<StorageType, List<StorageMetrics>> metricsHistory = new ConcurrentHashMap<>();
    private final Map<StorageType, Long> totalOperations = new ConcurrentHashMap<>();
    private final Map<StorageType, Long> successfulOperations = new ConcurrentHashMap<>();
    private final Map<StorageType, Long> totalBytesTransferred = new ConcurrentHashMap<>();
    private final Map<StorageType, Long> lastOperationTime = new ConcurrentHashMap<>();

    private final Map<String, AtomicLong> encryptionTimePerAlgorithm = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> encryptionOpsPerAlgorithm = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> encryptionBytesPerAlgorithm = new ConcurrentHashMap<>();

    
    // Encryption metrics
    private final AtomicLong totalEncryptionTime = new AtomicLong(0);
    private final AtomicLong totalEncryptionBytes = new AtomicLong(0);
    private final AtomicLong totalEncryptionOperations = new AtomicLong(0);
    private final AtomicLong totalEncryptionFailures = new AtomicLong(0);
    private String currentFile;
    
    // System metrics
    private final Map<String, Object> performanceMetrics = new ConcurrentHashMap<>();
    private final Map<String, Object> globalMetrics = new HashMap<>();
    
    public MetricsServiceImpl() {
        for (StorageType type : StorageType.values()) {
            currentMetrics.put(type, new StorageMetrics());
            metricsHistory.put(type, new ArrayList<>());
            totalOperations.put(type, 0L);
            successfulOperations.put(type, 0L);
            totalBytesTransferred.put(type, 0L);
            lastOperationTime.put(type, System.currentTimeMillis());
        }
    }

    @Override
    public void recordOperation(StorageType type, boolean success, long bytesTransferred) {
        if (type == null) {
            logger.warn("Attempted to record operation with null storage type");
            return;
        }
        
        try {
            totalOperations.merge(type, 1L, Long::sum);
            if (success) {
                successfulOperations.merge(type, 1L, Long::sum);
                if (bytesTransferred > 0) {
                    totalBytesTransferred.merge(type, bytesTransferred, Long::sum);
                }
            }
            lastOperationTime.put(type, System.currentTimeMillis());
        } catch (Exception e) {
            logger.error("Error recording operation for storage type {}: {}", type, e.getMessage(), e);
        }
    }

    @Override
    public void updateMetrics(StorageType type, StorageMetrics metrics) {
        if (type == null || metrics == null) {
            logger.warn("Attempted to update metrics with null type or metrics");
            return;
        }
        
        try {
            currentMetrics.put(type, metrics);
            
            // Add to history
            List<StorageMetrics> history = metricsHistory.get(type);
            if (history == null) {
                history = new ArrayList<>();
                metricsHistory.put(type, history);
            }
            history.add(metrics);
            if (history.size() > MAX_HISTORY_SIZE) {
                history.remove(0);
            }
        } catch (Exception e) {
            logger.error("Error updating metrics for storage type {}: {}", type, e.getMessage(), e);
        }
    }

    @Override
    public void updateMetrics(Map<String, Object> metrics) {
        if (metrics == null) {
            logger.warn("Attempted to update metrics with null metrics map");
            return;
        }
        
        try {
            performanceMetrics.putAll(metrics);
        } catch (Exception e) {
            logger.error("Error updating metrics: {}", e.getMessage(), e);
        }
    }

    @Override
    public Map<String, Object> getPerformanceMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        try {
            // Calculate overall success rate
            long totalOps = totalOperations.values().stream().mapToLong(Long::longValue).sum();
            long totalSuccess = successfulOperations.values().stream().mapToLong(Long::longValue).sum();
            double successRate = totalOps > 0 ? (double) totalSuccess / totalOps * 100 : 0.0;
            
            metrics.put("total_operations", totalOps);
            metrics.put("successful_operations", totalSuccess);
            metrics.put("success_rate", String.format("%.2f", successRate));
            
            // Add encryption metrics
            metrics.put("total_encryption_operations", totalEncryptionOperations.get());
            metrics.put("total_encryption_bytes", totalEncryptionBytes.get());
            metrics.put("total_encryption_time_ms", totalEncryptionTime.get());
            metrics.put("total_encryption_failures", totalEncryptionFailures.get());
            
            // Add storage metrics
            for (StorageType type : StorageType.values()) {
                String prefix = type.name().toLowerCase() + "_";
                StorageMetrics storageMetrics = currentMetrics.get(type);
                if (storageMetrics != null) {
                    metrics.put(prefix + "total_space", storageMetrics.getTotalSpace());
                    metrics.put(prefix + "used_space", storageMetrics.getUsedSpace());
                    metrics.put(prefix + "free_space", storageMetrics.getFreeSpace());
                    metrics.put(prefix + "cpu_usage", storageMetrics.getCpuUsage());
                    metrics.put(prefix + "memory_usage", storageMetrics.getMemoryUsage());
                    metrics.put(prefix + "network_throughput", storageMetrics.getNetworkThroughput());
                    metrics.put(prefix + "disk_latency", storageMetrics.getDiskLatency());
                    metrics.put(prefix + "active_connections", storageMetrics.getActiveConnections());
                }
            }
        } catch (Exception e) {
            logger.error("Error getting performance metrics: {}", e.getMessage(), e);
        }
        
        return metrics;
    }

    @Override
    public Map<StorageType, Double> getThroughput() {
        Map<StorageType, Double> throughput = new HashMap<>();
        long currentTime = System.currentTimeMillis();
        
        try {
            for (StorageType type : StorageType.values()) {
                long timeDiff = currentTime - lastOperationTime.get(type);
                long bytes = totalBytesTransferred.get(type);
                
                double throughputMBps = timeDiff > 0 ? 
                    (bytes / (1024.0 * 1024.0)) / (timeDiff / 1000.0) : 0.0;
                
                throughput.put(type, throughputMBps);
            }
        } catch (Exception e) {
            logger.error("Error calculating throughput: {}", e.getMessage(), e);
        }
        
        return throughput;
    }

    @Override
    public void setCurrentFile(String fileName) {
        this.currentFile = fileName;
    }

    @Override
    public void clearCurrentFile() {
        this.currentFile = null;
    }

    @Override
    public void recordEncryptionOperation(String algorithm, long bytesProcessed, long timeMs) {
        if (algorithm == null || algorithm.isEmpty()) {
            logger.warn("Attempted to record encryption operation with null or empty algorithm");
            return;
        }
        
        try {
            totalEncryptionOperations.incrementAndGet();
            encryptionTimePerAlgorithm.computeIfAbsent(algorithm, k -> new AtomicLong()).addAndGet(timeMs);
            encryptionOpsPerAlgorithm.computeIfAbsent(algorithm, k -> new AtomicLong()).incrementAndGet();
            encryptionBytesPerAlgorithm.computeIfAbsent(algorithm, k -> new AtomicLong()).addAndGet(bytesProcessed);

            if (bytesProcessed > 0) {
                totalEncryptionBytes.addAndGet(bytesProcessed);
            }
            if (timeMs > 0) {
                totalEncryptionTime.addAndGet(timeMs);
            }
        } catch (Exception e) {
            logger.error("Error recording encryption operation: {}", e.getMessage(), e);
        }
    }

    @Override
    public void recordDecryptionOperation(String algorithm, long bytesProcessed, long timeMs) {
        if (algorithm == null || algorithm.isEmpty()) {
            logger.warn("Attempted to record decryption operation with null or empty algorithm");
            return;
        }
        
        try {
            totalEncryptionOperations.incrementAndGet();
            encryptionTimePerAlgorithm.computeIfAbsent(algorithm, k -> new AtomicLong()).addAndGet(timeMs);
            encryptionOpsPerAlgorithm.computeIfAbsent(algorithm, k -> new AtomicLong()).incrementAndGet();
            encryptionBytesPerAlgorithm.computeIfAbsent(algorithm, k -> new AtomicLong()).addAndGet(bytesProcessed);

            if (bytesProcessed > 0) {
                totalEncryptionBytes.addAndGet(bytesProcessed);
            }
            if (timeMs > 0) {
                totalEncryptionTime.addAndGet(timeMs);
            }
        } catch (Exception e) {
            logger.error("Error recording decryption operation: {}", e.getMessage(), e);
        }
    }

    @Override
    public void handleEncryptionFailure(String fileName, Exception e) {
        if (fileName == null || e == null) {
            logger.warn("Attempted to handle encryption failure with null fileName or exception");
            return;
        }
        
        try {
            totalEncryptionFailures.incrementAndGet();
            logger.error("Encryption failure for file: {}", fileName, e);
        } catch (Exception ex) {
            logger.error("Error handling encryption failure: {}", ex.getMessage(), ex);
        }
    }

    @Override
    public void clearMetrics() {
        try {
            for (StorageType type : StorageType.values()) {
                totalOperations.put(type, 0L);
                successfulOperations.put(type, 0L);
                totalBytesTransferred.put(type, 0L);
                lastOperationTime.put(type, System.currentTimeMillis());
                metricsHistory.get(type).clear();
            }
            totalEncryptionTime.set(0);
            totalEncryptionBytes.set(0);
            totalEncryptionOperations.set(0);
            totalEncryptionFailures.set(0);
            performanceMetrics.clear();
            globalMetrics.clear();
        } catch (Exception e) {
            logger.error("Error clearing metrics: {}", e.getMessage(), e);
        }
    }

    @Override
    public void recordBasicIOOperation(int bytesRead, int bytesWritten, long timeMs) {
        try {
            if (bytesRead > 0) {
                totalBytesTransferred.merge(StorageType.LOCAL, (long) bytesRead, Long::sum);
            }
            if (bytesWritten > 0) {
                totalBytesTransferred.merge(StorageType.LOCAL, (long) bytesWritten, Long::sum);
            }
            if (timeMs > 0) {
                // Update performance metrics with I/O operation time
                Map<String, Object> metrics = new HashMap<>();
                metrics.put("io_operation_time_ms", timeMs);
                updateMetrics(metrics);
            }
        } catch (Exception e) {
            logger.error("Error recording basic I/O operation: {}", e.getMessage(), e);
        }
    }

    // Non-interface methods that should be kept
    public Map<StorageType, StorageMetrics> getCurrentMetrics() {
        return new HashMap<>(currentMetrics);
    }

    public Map<StorageType, List<StorageMetrics>> getMetricsHistory() {
        return new HashMap<>(metricsHistory);
    }

    public Map<StorageType, Long> getTotalOperations() {
        return new HashMap<>(totalOperations);
    }

    public Map<StorageType, Long> getSuccessfulOperations() {
        return new HashMap<>(successfulOperations);
    }

    public Map<StorageType, Long> getTotalBytesTransferred() {
        return new HashMap<>(totalBytesTransferred);
    }

    public Map<StorageType, Long> getLastOperationTime() {
        return new HashMap<>(lastOperationTime);
    }

    public double getSuccessRate(StorageType type) {
        if (type == null) {
            logger.warn("Attempted to get success rate for null storage type");
            return 0.0;
        }
        
        try {
            long total = totalOperations.getOrDefault(type, 0L);
            long success = successfulOperations.getOrDefault(type, 0L);
            return total > 0 ? (double) success / total * 100 : 0.0;
        } catch (Exception e) {
            logger.error("Error calculating success rate for storage type {}: {}", type, e.getMessage(), e);
            return 0.0;
        }
    }

    public void updatePerformanceMetrics(Map<String, Object> metrics) {
        if (metrics == null) {
            logger.warn("Attempted to update performance metrics with null metrics");
            return;
        }
        
        try {
            performanceMetrics.putAll(metrics);
        } catch (Exception e) {
            logger.error("Error updating performance metrics: {}", e.getMessage(), e);
        }
    }

    public void updateGlobalMetrics(Map<String, Object> metrics) {
        if (metrics == null) {
            logger.warn("Attempted to update global metrics with null metrics");
            return;
        }
        
        try {
            globalMetrics.putAll(metrics);
        } catch (Exception e) {
            logger.error("Error updating global metrics: {}", e.getMessage(), e);
        }
    }

    public Map<String, Object> getGlobalMetrics() {
        return new HashMap<>(globalMetrics);
    }
} 