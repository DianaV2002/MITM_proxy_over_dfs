package org.example.services;

import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import com.sun.management.OperatingSystemMXBean;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.concurrent.TimeUnit;

@Service
public class PerformanceMetricsService {
    private static final Logger logger = LoggerFactory.getLogger(PerformanceMetricsService.class);
    
    // Encryption Performance Metrics
    private final Map<String, List<EncryptionMetric>> encryptionMetrics = new ConcurrentHashMap<>();
    private final Map<String, List<DecryptionMetric>> decryptionMetrics = new ConcurrentHashMap<>();
    
    // Latency Metrics
    private final Map<String, List<LatencyMetric>> proxyLatencyMetrics = new ConcurrentHashMap<>();
    
    // Agent-reported metrics
    private final Map<String, Map<String, Object>> agentMetrics = new ConcurrentHashMap<>();
    
    // Resource monitoring
    private final OperatingSystemMXBean osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
    private final MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
    
    private final Map<String, AtomicLong> operationLatencies = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> operationCounts = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> proxyLatencies = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> encryptionTimes = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> decryptionTimes = new ConcurrentHashMap<>();
    private final AtomicLong totalEncryptionTime = new AtomicLong(0);
    private final AtomicLong totalDecryptionTime = new AtomicLong(0);
    private final AtomicLong encryptionOperations = new AtomicLong(0);
    private final AtomicLong decryptionOperations = new AtomicLong(0);
    private final AtomicReference<String> currentAlgorithm = new AtomicReference<>();
    private final AtomicLong totalBytesProcessed = new AtomicLong(0);
    private final AtomicLong totalBytesRead = new AtomicLong(0);
    private final AtomicLong totalBytesWritten = new AtomicLong(0);
    private final AtomicLong totalOperations = new AtomicLong(0);
    
    private final Map<String, List<Long>> encryptionLatencies = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> decryptionLatencies = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> agentLatencies = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> vaultLatencies = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> storageLatencies = new ConcurrentHashMap<>();

    
    private final Map<String, AtomicLong> encryptionTimePerAlgorithm = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> encryptionOpsPerAlgorithm = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> encryptionBytesPerAlgorithm = new ConcurrentHashMap<>();

    
    private final Map<String, AtomicLong> encryptionThroughput = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> decryptionThroughput = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> storageThroughput = new ConcurrentHashMap<>();
    
    private final Map<String, AtomicLong> vaultCacheHits = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> vaultCacheMisses = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> vaultKeyRetrievalLatency = new ConcurrentHashMap<>();
    
    private final Map<String, AtomicLong> memoryUsage = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> cpuUsage = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> nonHeapMemoryUsage = new ConcurrentHashMap<>();
    
    public PerformanceMetricsService() {
        logger.info("Initializing PerformanceMetricsService");
        startSystemMetricsUpdateThread();
    }
    
    private void startSystemMetricsUpdateThread() {
        Thread metricsThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    // Update system metrics every second
                    updateSystemMetrics();
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logger.error("Error updating system metrics: {}", e.getMessage());
                }
            }
        });
        metricsThread.setDaemon(true);
        metricsThread.setName("SystemMetricsUpdater");
        metricsThread.start();
        logger.info("Started system metrics update thread");
    }
    
    private void updateSystemMetrics() {
        try {
            // Get current system metrics
            long memoryUsage = memoryBean.getHeapMemoryUsage().getUsed();
            long nonHeapMemory = memoryBean.getNonHeapMemoryUsage().getUsed();
            double cpuLoad = osBean.getSystemCpuLoad() * 100;
            
            // Record the metrics
            recordSystemMetrics(memoryUsage, (long)cpuLoad, nonHeapMemory);
            
            logger.debug("Updated system metrics - CPU: {}%, Memory: {} bytes, Non-Heap: {} bytes", 
                cpuLoad, memoryUsage, nonHeapMemory);
        } catch (Exception e) {
            logger.error("Error updating system metrics: {}", e.getMessage());
        }
    }
    
    public void recordEncryptionOperation(String algorithm, long bytesProcessed, long timeMs) {
        encryptionLatencies.computeIfAbsent(algorithm, k -> new ArrayList<>()).add(timeMs);
        
        // Calculate throughput in MB/s
        double throughput = (bytesProcessed / (1024.0 * 1024.0)) / (timeMs / 1000.0);
        encryptionThroughput.computeIfAbsent(algorithm, k -> new AtomicLong(0))
            .set((long)(throughput * 1000)); // Store as MB/s * 1000 for precision
        
        logger.info("Encryption operation - Algorithm: {}, Throughput: {:.2f} MB/s, Time: {}ms", 
            algorithm, throughput, timeMs);
    }
    
    public void recordDecryptionOperation(String algorithm, long size, long time) {
        decryptionTimes.computeIfAbsent(algorithm, k -> new ArrayList<>())
                      .add(time);
        logger.info("Recorded decryption operation for {}: {} ms, {} bytes", algorithm, time, size);
        DecryptionMetric metric = new DecryptionMetric(
            algorithm,
            size,
            time,
            calculateThroughput(size, time)
        );
        decryptionMetrics.computeIfAbsent(algorithm, k -> new ArrayList<>()).add(metric);
        logger.debug("Recorded decryption metric: {} MB/s for algorithm: {}", 
            metric.getThroughputMBps(), algorithm);
        totalDecryptionTime.addAndGet(time);
        decryptionOperations.incrementAndGet();
        totalBytesProcessed.addAndGet(size);
        currentAlgorithm.set(algorithm);
        totalOperations.incrementAndGet();
    }
    
    public void recordProxyLatency(String operation, long baselineTime, long totalTime) {
        proxyLatencies.computeIfAbsent(operation, k -> new ArrayList<>())
                     .add(totalTime - baselineTime);
        logger.info("Recorded proxy latency for {}: {} ms", operation, totalTime - baselineTime);
        double latencyOverhead = ((double)(totalTime - baselineTime) / baselineTime) * 100;
        LatencyMetric metric = new LatencyMetric(operation, baselineTime, totalTime, latencyOverhead);
        proxyLatencyMetrics.computeIfAbsent(operation, k -> new ArrayList<>()).add(metric);
        logger.debug("Recorded latency overhead: {}% for operation: {}", latencyOverhead, operation);
        operationLatencies.computeIfAbsent(operation, k -> new AtomicLong(0))
                         .addAndGet(totalTime - baselineTime);
        operationCounts.computeIfAbsent(operation, k -> new AtomicLong(0))
                      .incrementAndGet();
        totalOperations.incrementAndGet();
    }
    
    public void recordBytesRead(long bytes) {
        totalBytesRead.addAndGet(bytes);
        logger.info("Recorded bytes read: {}", bytes);
    }
    
    public void recordBytesWritten(long bytes) {
        totalBytesWritten.addAndGet(bytes);
        logger.info("Recorded bytes written: {}", bytes);
    }
    
    // Method to receive metrics from C-based agents
    public void updateAgentMetrics(String agentId, Map<String, Object> metrics) {
        agentMetrics.put(agentId, metrics);
        logger.debug("Updated metrics from agent {}: {}", agentId, metrics);
    }
    // @Override
public Map<String, Object> getDetailedPerformanceMetrics() {
    Map<String, Object> metrics = new HashMap<>();

    // Proxy latencies
    Map<String, Object> proxyPerformance = new HashMap<>();
    proxyLatencies.forEach((operation, latencies) -> {
        double avgLatency = latencies.stream().mapToLong(Long::longValue).average().orElse(0.0);
        proxyPerformance.put(operation, avgLatency);
    });
    metrics.put("proxy_performance", proxyPerformance);

    // Encryption algorithm performance
    Map<String, Object> algoPerformance = new HashMap<>();
    for (String algo : encryptionTimePerAlgorithm.keySet()) {
        long ops = encryptionOpsPerAlgorithm.getOrDefault(algo, new AtomicLong()).get();
        long time = encryptionTimePerAlgorithm.getOrDefault(algo, new AtomicLong()).get();
        long bytes = encryptionBytesPerAlgorithm.getOrDefault(algo, new AtomicLong()).get();

        double avgTimeMs = ops > 0 ? (double) time / ops : 0;
        double throughputMB = time > 0 ? (bytes / (1024.0 * 1024.0)) / (time / 1000.0) : 0;

        Map<String, Object> algoStats = new HashMap<>();
        algoStats.put("operations", ops);
        algoStats.put("avg_time_ms", avgTimeMs);
        algoStats.put("throughput_mb", throughputMB);
        // Optionally, overhead_percent could use a baseline latency
       // algoStats.put("overhead_percent", latencyBaselineEstimate > 0 ? (avgTimeMs / latencyBaselineEstimate) * 100 : 0);

        algoPerformance.put(algo, algoStats);
    }
    metrics.put("algorithm_performance", algoPerformance);

    // Encryption summary
    Map<String, Object> encryptionPerformance = new HashMap<>();
    encryptionTimes.forEach((algorithm, times) -> {
        Map<String, Object> stats = new HashMap<>();
        double avgTime = times.stream().mapToLong(Long::longValue).average().orElse(0.0);
        int opCount = times.size();
        double throughput = opCount > 0 ? (totalBytesRead.get() / (1024.0 * 1024.0)) / (avgTime / 1000.0) : 0.0;

        stats.put("average_time_ms", avgTime);
        stats.put("operations_count", opCount);
        stats.put("throughput_mb", throughput);

        encryptionPerformance.put(algorithm, stats);
    });
    metrics.put("encryption_performance", encryptionPerformance);

    // Decryption summary
    Map<String, Object> decryptionPerformance = new HashMap<>();
    decryptionTimes.forEach((algorithm, times) -> {
        Map<String, Object> stats = new HashMap<>();
        double avgTime = times.stream().mapToLong(Long::longValue).average().orElse(0.0);
        int opCount = times.size();
        double throughput = opCount > 0 ? (totalBytesWritten.get() / (1024.0 * 1024.0)) / (avgTime / 1000.0) : 0.0;

        stats.put("average_time_ms", avgTime);
        stats.put("operations_count", opCount);
        stats.put("throughput_mb", throughput);

        decryptionPerformance.put(algorithm, stats);
    });
    metrics.put("decryption_performance", decryptionPerformance);

    // Latency metrics
    Map<String, Object> latencyMetrics = new HashMap<>();
    for (Map.Entry<String, List<LatencyMetric>> entry : proxyLatencyMetrics.entrySet()) {
        Map<String, Double> stats = calculateLatencyStats(entry.getValue());
        latencyMetrics.put(entry.getKey(), stats);
    }
    metrics.put("latency_overhead", latencyMetrics);

    // Agent metrics (external sources)
    metrics.put("agent_metrics", agentMetrics);

    return metrics;
}

    private Map<String, Double> calculateAlgorithmStats(List<? extends EncryptionMetric> metrics) {
        Map<String, Double> stats = new HashMap<>();
        
        DoubleSummaryStatistics throughputStats = metrics.stream()
            .mapToDouble(EncryptionMetric::getThroughputMBps)
            .summaryStatistics();
            
        stats.put("avg_throughput", throughputStats.getAverage());
        stats.put("max_throughput", throughputStats.getMax());
        stats.put("min_throughput", throughputStats.getMin());
        stats.put("operations_count", (double) metrics.size());
        
        return stats;
    }
    
    private Map<String, Double> calculateLatencyStats(List<LatencyMetric> metrics) {
        Map<String, Double> stats = new HashMap<>();
        
        DoubleSummaryStatistics overheadStats = metrics.stream()
            .mapToDouble(m -> m.latencyOverhead)
            .summaryStatistics();
            
        stats.put("avg_overhead_percent", overheadStats.getAverage());
        stats.put("max_overhead_percent", overheadStats.getMax());
        stats.put("min_overhead_percent", overheadStats.getMin());
        stats.put("operations_count", (double) metrics.size());
        
        return stats;
    }
    
    private double calculateThroughput(long bytes, long milliseconds) {
        if (milliseconds == 0) return 0;
        return (bytes / 1024.0 / 1024.0) / (milliseconds / 1000.0); // MB/s
    }
    
    // Metric Classes
    private static class EncryptionMetric {
        private final String algorithm;
        private final long fileSize;
        private final long duration;
        private final double throughputMBps;
        
        public EncryptionMetric(String algorithm, long fileSize, long duration, double throughputMBps) {
            this.algorithm = algorithm;
            this.fileSize = fileSize;
            this.duration = duration;
            this.throughputMBps = throughputMBps;
        }
        
        public double getThroughputMBps() { return throughputMBps; }
    }
    
    private static class DecryptionMetric extends EncryptionMetric {
        public DecryptionMetric(String algorithm, long fileSize, long duration, double throughputMBps) {
            super(algorithm, fileSize, duration, throughputMBps);
        }
    }
    
    private static class LatencyMetric {
        private final String operation;
        private final long baselineDuration;
        private final long actualDuration;
        private final double latencyOverhead;
        
        public LatencyMetric(String operation, long baselineDuration, long actualDuration, double latencyOverhead) {
            this.operation = operation;
            this.baselineDuration = baselineDuration;
            this.actualDuration = actualDuration;
            this.latencyOverhead = latencyOverhead;
        }
    }
    
    public void clearMetrics() {
        logger.info("Clearing all performance metrics");
        operationLatencies.clear();
        operationCounts.clear();
        proxyLatencies.clear();
        encryptionTimes.clear();
        decryptionTimes.clear();
        totalEncryptionTime.set(0);
        totalDecryptionTime.set(0);
        encryptionOperations.set(0);
        decryptionOperations.set(0);
        totalBytesProcessed.set(0);
        totalBytesRead.set(0);
        totalBytesWritten.set(0);
        totalOperations.set(0);
        currentAlgorithm.set(null);
        encryptionMetrics.clear();
        decryptionMetrics.clear();
        proxyLatencyMetrics.clear();
        agentMetrics.clear();
        encryptionLatencies.clear();
        decryptionLatencies.clear();
        agentLatencies.clear();
        vaultLatencies.clear();
        storageLatencies.clear();
        encryptionThroughput.clear();
        decryptionThroughput.clear();
        storageThroughput.clear();
        vaultCacheHits.clear();
        vaultCacheMisses.clear();
        vaultKeyRetrievalLatency.clear();
        memoryUsage.clear();
        cpuUsage.clear();
        nonHeapMemoryUsage.clear();
    }

    public void recordVaultOperation(String operation, long timeMs, boolean isCacheHit) {
        vaultLatencies.computeIfAbsent(operation, k -> new ArrayList<>()).add(timeMs);
        
        if (isCacheHit) {
            vaultCacheHits.computeIfAbsent(operation, k -> new AtomicLong(0)).incrementAndGet();
        } else {
            vaultCacheMisses.computeIfAbsent(operation, k -> new AtomicLong(0)).incrementAndGet();
        }
        
        if ("key_retrieval".equals(operation)) {
            vaultKeyRetrievalLatency.computeIfAbsent(operation, k -> new AtomicLong(0))
                .addAndGet(timeMs);
        }
        
        logger.info("Vault operation - Type: {}, Cache Hit: {}, Time: {}ms", 
            operation, isCacheHit, timeMs);
    }

    public void recordStorageOperation(String storageType, String operation, long timeMs, boolean success) {
        storageLatencies.computeIfAbsent(storageType + "_" + operation, k -> new ArrayList<>())
            .add(timeMs);
        
        if ("upload".equals(operation)) {
            // Calculate throughput in MB/s
            double throughput = (1024.0) / (timeMs / 1000.0); // Assuming 1MB chunks
            storageThroughput.computeIfAbsent(storageType, k -> new AtomicLong(0))
                .set((long)(throughput * 1000)); // Store as MB/s * 1000 for precision
        }
        
        logger.info("Storage operation - Type: {}, Operation: {}, Time: {}ms, Success: {}", 
            storageType, operation, timeMs, success);
    }

    public void recordSystemMetrics(long memoryUsageBytes, long cpuUsagePercent, long nonHeapMemoryBytes) {
        memoryUsage.put("current", new AtomicLong(memoryUsageBytes));
        cpuUsage.put("current", new AtomicLong(cpuUsagePercent));
        nonHeapMemoryUsage.put("current", new AtomicLong(nonHeapMemoryBytes));
        
        logger.debug("System metrics - Memory: {} MB, CPU: {}%, Non-Heap: {} MB", 
            memoryUsageBytes / (1024.0 * 1024.0),
            cpuUsagePercent,
            nonHeapMemoryBytes / (1024.0 * 1024.0));
    }

    public Map<String, Object> getPerformanceMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        // Encryption metrics
        encryptionLatencies.forEach((algorithm, latencies) -> {
            double avgLatency = latencies.stream().mapToLong(Long::longValue).average().orElse(0);
            double throughput = encryptionThroughput.getOrDefault(algorithm, new AtomicLong(0)).get() / 1000.0;
            
            metrics.put(algorithm + "_encryption_avg_latency", String.format("%.2f", avgLatency));
            metrics.put(algorithm + "_encryption_throughput", String.format("%.2f", throughput));
        });
        
        // Vault metrics
        vaultLatencies.forEach((operation, latencies) -> {
            double avgLatency = latencies.stream().mapToLong(Long::longValue).average().orElse(0);
            long hits = vaultCacheHits.getOrDefault(operation, new AtomicLong(0)).get();
            long misses = vaultCacheMisses.getOrDefault(operation, new AtomicLong(0)).get();
            long totalOps = hits + misses;
            double cacheHitRate = totalOps > 0 ? (hits * 100.0) / totalOps : 0.0;
            
            metrics.put(operation + "_vault_avg_latency", String.format("%.2f", avgLatency));
            metrics.put(operation + "_vault_cache_hit_rate", String.format("%.2f", cacheHitRate));
        });
        
        // Storage metrics
        storageLatencies.forEach((key, latencies) -> {
            double avgLatency = latencies.stream().mapToLong(Long::longValue).average().orElse(0);
            String[] parts = key.split("_");
            String storageType = parts[0];
            String operation = parts[1];
            
            metrics.put(storageType + "_" + operation + "_avg_latency", 
                String.format("%.2f", avgLatency));
            
            if ("upload".equals(operation)) {
                double throughput = storageThroughput.getOrDefault(storageType, new AtomicLong(0)).get() / 1000.0;
                metrics.put(storageType + "_upload_throughput", 
                    String.format("%.2f", throughput));
            }
        });
        
        // System metrics
        metrics.put("memory_usage_mb", 
            String.format("%.2f", memoryUsage.getOrDefault("current", new AtomicLong(0)).get() / (1024.0 * 1024.0)));
        metrics.put("cpu_usage_percent", 
            String.format("%.2f", cpuUsage.getOrDefault("current", new AtomicLong(0)).get()));
        metrics.put("non_heap_memory_mb", 
            String.format("%.2f", nonHeapMemoryUsage.getOrDefault("current", new AtomicLong(0)).get() / (1024.0 * 1024.0)));
        
        return metrics;
    }
} 