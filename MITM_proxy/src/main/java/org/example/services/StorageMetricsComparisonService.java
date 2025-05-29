package org.example.services;

import org.apache.hadoop.fs.StorageType;
import org.example.model.StorageMetrics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

@Service
public class StorageMetricsComparisonService {
    private static final Logger logger = LoggerFactory.getLogger(StorageMetricsComparisonService.class);
    private static final int MAX_HISTORY_SIZE = 100;
    private static final long GB = 1024 * 1024 * 1024;

    private final Map<StorageType, StorageMetrics> currentMetrics = new ConcurrentHashMap<>();
    private final Map<StorageType, List<StorageMetrics>> metricsHistory = new ConcurrentHashMap<>();
    private final Map<StorageType, Long> lastUpdateTime = new ConcurrentHashMap<>();
    private final Map<StorageType, Long> totalOperations = new ConcurrentHashMap<>();
    private final Map<StorageType, Long> successfulOperations = new ConcurrentHashMap<>();
    private final Map<StorageType, Long> totalBytesTransferred = new ConcurrentHashMap<>();
    private final Map<StorageType, Long> lastOperationTime = new ConcurrentHashMap<>();
    private final Map<StorageType, Long> totalSpace = new ConcurrentHashMap<>();
    private final Map<StorageType, Long> usedSpace = new ConcurrentHashMap<>();

    public StorageMetricsComparisonService() {
        for (StorageType type : StorageType.values()) {
            currentMetrics.put(type, new StorageMetrics());
            metricsHistory.put(type, new ArrayList<>());
            totalOperations.put(type, 0L);
            successfulOperations.put(type, 0L);
            totalBytesTransferred.put(type, 0L);
            lastOperationTime.put(type, System.currentTimeMillis());
            totalSpace.put(type, 0L);
            usedSpace.put(type, 0L);
        }
    }

    public void updateMetrics(StorageType type, StorageMetrics metrics) {
        if (metrics == null) {
            logger.warn("Received null metrics for storage type: {}", type);
            return;
        }

        // Update space metrics
        totalSpace.put(type, metrics.getTotalSpace());
        usedSpace.put(type, metrics.getUsedSpace());

        // Update current metrics
        currentMetrics.put(type, metrics);

        // Add to history
        List<StorageMetrics> history = metricsHistory.get(type);
        history.add(metrics);
        
        if (history.size() > MAX_HISTORY_SIZE) {
            history.remove(0);
        }

        lastUpdateTime.put(type, System.currentTimeMillis());
    }

    public void recordOperation(StorageType type, boolean success, long bytesTransferred) {
        totalOperations.merge(type, 1L, Long::sum);
        if (success) {
            successfulOperations.merge(type, 1L, Long::sum);
            usedSpace.merge(type, bytesTransferred, Long::sum);
        }
        totalBytesTransferred.merge(type, bytesTransferred, Long::sum);
        lastOperationTime.put(type, System.currentTimeMillis());
    }

    public Map<StorageType, StorageMetrics> getCurrentMetrics() {
        return new HashMap<>(currentMetrics);
    }

    public Map<StorageType, List<StorageMetrics>> getMetricsHistory() {
        return new HashMap<>(metricsHistory);
    }

    public Map<StorageType, Double> getSuccessRates() {
        Map<StorageType, Double> successRates = new HashMap<>();
        for (StorageType type : StorageType.values()) {
            long total = totalOperations.get(type);
            long successful = successfulOperations.get(type);
            successRates.put(type, total > 0 ? (double) successful / total * 100 : 0.0);
        }
        return successRates;
    }

    public Map<StorageType, Double> getThroughput() {
        Map<StorageType, Double> throughput = new HashMap<>();
        long currentTime = System.currentTimeMillis();
        
        for (StorageType type : StorageType.values()) {
            long timeDiff = currentTime - lastOperationTime.get(type);
            long bytes = totalBytesTransferred.get(type);
            
            double throughputMBps = timeDiff > 0 ? 
                (bytes / (1024.0 * 1024.0)) / (timeDiff / 1000.0) : 0.0;
            
            throughput.put(type, throughputMBps);
        }
        return throughput;
    }

    public Map<StorageType, Long> getLastUpdateTimes() {
        return new HashMap<>(lastUpdateTime);
    }

    public Map<StorageType, Double> getSpaceUtilization() {
        Map<StorageType, Double> utilization = new HashMap<>();
        for (StorageType type : StorageType.values()) {
            long total = totalSpace.get(type);
            long used = usedSpace.get(type);
            utilization.put(type, total > 0 ? (double) used / total * 100 : 0.0);
        }
        return utilization;
    }

    public Map<StorageType, Double> getFreeSpaceGB() {
        Map<StorageType, Double> freeSpace = new HashMap<>();
        for (StorageType type : StorageType.values()) {
            long total = totalSpace.get(type);
            long used = usedSpace.get(type);
            freeSpace.put(type, (total - used) / (double) GB);
        }
        return freeSpace;
    }

    public Map<StorageType, Double> getTotalSpaceGB() {
        Map<StorageType, Double> totalSpaceGB = new HashMap<>();
        for (StorageType type : StorageType.values()) {
            totalSpaceGB.put(type, totalSpace.get(type) / (double) GB);
        }
        return totalSpaceGB;
    }

    public Map<StorageType, Double> getUsedSpaceGB() {
        Map<StorageType, Double> usedSpaceGB = new HashMap<>();
        for (StorageType type : StorageType.values()) {
            usedSpaceGB.put(type, usedSpace.get(type) / (double) GB);
        }
        return usedSpaceGB;
    }
} 