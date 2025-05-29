package org.example.controllers;

import org.example.services.MetricsServiceImpl;
import org.example.services.PerformanceMetricsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

@RestController
@RequestMapping("/api/metrics")
public class MetricsController {
    
    @Autowired
    private MetricsServiceImpl metricsService;
    
    @Autowired
    private PerformanceMetricsService performanceMetrics;
    
    @GetMapping
    public Map<String, Object> getAllMetrics() {
        Map<String, Object> allMetrics = new HashMap<>();
        
        // Get basic metrics
        Map<String, Object> basicMetrics = metricsService.getPerformanceMetrics();
        allMetrics.put("basic", basicMetrics);
        
        // Get detailed performance metrics
        Map<String, Object> detailedMetrics = performanceMetrics.getDetailedPerformanceMetrics();
        allMetrics.put("detailed", detailedMetrics);
        
        // Add proxy-specific metrics
        Map<String, Object> proxyMetrics = new HashMap<>();
        proxyMetrics.put("proxy_performance", calculateProxyPerformance(basicMetrics, detailedMetrics));
        proxyMetrics.put("encryption_performance", calculateEncryptionPerformance(detailedMetrics));
        proxyMetrics.put("resource_utilization", detailedMetrics.get("resource_utilization"));
        
        // Merge proxy metrics into detailed metrics instead of overwriting
        detailedMetrics.putAll(proxyMetrics);
        allMetrics.put("detailed", detailedMetrics);
        
        return allMetrics;
    }
    
    private Map<String, Object> calculateProxyPerformance(Map<String, Object> basicMetrics, Map<String, Object> detailedMetrics) {
        Map<String, Object> proxyPerformance = new HashMap<>();
        
        // Calculate proxy latency
        long totalOperations = (long) basicMetrics.getOrDefault("totalOperations", 0L);
        long totalTime = (long) basicMetrics.getOrDefault("totalTime", 0L);
        long baselineTime = (long) basicMetrics.getOrDefault("baselineTime", 0L);
        
        double latencyMs = totalOperations > 0 ? (double) totalTime / totalOperations : 0;
        double baselineLatencyMs = totalOperations > 0 ? (double) baselineTime / totalOperations : 0;
        double latencyOverhead = baselineLatencyMs > 0 ? ((latencyMs - baselineLatencyMs) / baselineLatencyMs) * 100 : 0;
        
        proxyPerformance.put("latency_ms", latencyMs);
        proxyPerformance.put("latency_overhead", latencyOverhead);
        
        // Calculate request processing time
        Map<String, Object> requestMetrics = (Map<String, Object>) detailedMetrics.getOrDefault("request_processing", new HashMap<>());
        double requestProcessingMs = (double) requestMetrics.getOrDefault("average_time_ms", 0.0);
        double requestBaselineMs = (double) requestMetrics.getOrDefault("baseline_time_ms", 0.0);
        double requestOverhead = requestBaselineMs > 0 ? ((requestProcessingMs - requestBaselineMs) / requestBaselineMs) * 100 : 0;
        
        proxyPerformance.put("request_processing_ms", requestProcessingMs);
        proxyPerformance.put("request_overhead", requestOverhead);
        
        // Calculate response processing time
        Map<String, Object> responseMetrics = (Map<String, Object>) detailedMetrics.getOrDefault("response_processing", new HashMap<>());
        double responseProcessingMs = (double) responseMetrics.getOrDefault("average_time_ms", 0.0);
        double responseBaselineMs = (double) responseMetrics.getOrDefault("baseline_time_ms", 0.0);
        double responseOverhead = responseBaselineMs > 0 ? ((responseProcessingMs - responseBaselineMs) / responseBaselineMs) * 100 : 0;
        
        proxyPerformance.put("response_processing_ms", responseProcessingMs);
        proxyPerformance.put("response_overhead", responseOverhead);
        
        // Calculate total proxy overhead
        double totalOverhead = (latencyOverhead + requestOverhead + responseOverhead) / 3;
        proxyPerformance.put("total_overhead", totalOverhead);
        
        return proxyPerformance;
    }
    
    private Map<String, Object> calculateEncryptionPerformance(Map<String, Object> detailedMetrics) {
        Map<String, Object> encryptionPerformance = new HashMap<>();
        
        // Get encryption metrics
        Map<String, Object> encryptionMetrics = (Map<String, Object>) detailedMetrics.getOrDefault("encryption", new HashMap<>());
        double encryptionThroughput = (double) encryptionMetrics.getOrDefault("throughput_mb", 0.0);
        double encryptionOverhead = (double) encryptionMetrics.getOrDefault("overhead_percent", 0.0);
        
        encryptionPerformance.put("throughput_mb", encryptionThroughput);
        encryptionPerformance.put("overhead", encryptionOverhead);
        
        // Get decryption metrics
        Map<String, Object> decryptionMetrics = (Map<String, Object>) detailedMetrics.getOrDefault("decryption", new HashMap<>());
        double decryptionThroughput = (double) decryptionMetrics.getOrDefault("throughput_mb", 0.0);
        double decryptionOverhead = (double) decryptionMetrics.getOrDefault("overhead_percent", 0.0);
        
        encryptionPerformance.put("decryption_throughput_mb", decryptionThroughput);
        encryptionPerformance.put("decryption_overhead", decryptionOverhead);
        
        // Calculate algorithm performance
        Map<String, Object> algorithmMetrics = (Map<String, Object>) detailedMetrics.getOrDefault("algorithm_performance", new HashMap<>());
        double avgAlgorithmThroughput = 0.0;
        double avgAlgorithmOverhead = 0.0;
        int algorithmCount = 0;
        
        for (Object value : algorithmMetrics.values()) {
            if (value instanceof Map) {
                Map<String, Object> stats = (Map<String, Object>) value;
                avgAlgorithmThroughput += (double) stats.getOrDefault("throughput_mb", 0.0);
                avgAlgorithmOverhead += (double) stats.getOrDefault("overhead_percent", 0.0);
                algorithmCount++;
            }
        }
        
        if (algorithmCount > 0) {
            avgAlgorithmThroughput /= algorithmCount;
            avgAlgorithmOverhead /= algorithmCount;
        }
        
        encryptionPerformance.put("algorithm_throughput", avgAlgorithmThroughput);
        encryptionPerformance.put("algorithm_overhead", avgAlgorithmOverhead);
        
        return encryptionPerformance;
    }
    
    @GetMapping("/report")
    public Map<String, Object> generateReport() {
        Map<String, Object> report = new HashMap<>();
        
        // Get all metrics
        Map<String, Object> allMetrics = getAllMetrics();
        
        // Add timestamp and summary
        report.put("timestamp", System.currentTimeMillis());
        report.put("summary", generateSummary(allMetrics));
        
        // Add detailed sections
        report.put("proxy_performance", allMetrics.get("detailed"));
        
        // Add recommendations based on metrics
        report.put("recommendations", generateRecommendations(allMetrics));
        
        return report;
    }
    
    private Map<String, Object> generateSummary(Map<String, Object> metrics) {
        Map<String, Object> summary = new HashMap<>();
        
        // Get proxy performance metrics
        Map<String, Object> proxyMetrics = (Map<String, Object>) ((Map<String, Object>) metrics.get("detailed")).get("proxy_performance");
        summary.put("total_proxy_overhead", proxyMetrics.get("total_overhead"));
        summary.put("average_latency", proxyMetrics.get("latency_ms"));
        
        // Get encryption performance metrics
        Map<String, Object> encMetrics = (Map<String, Object>) ((Map<String, Object>) metrics.get("detailed")).get("encryption_performance");
        summary.put("encryption_throughput", encMetrics.get("throughput_mb"));
        summary.put("decryption_throughput", encMetrics.get("decryption_throughput_mb"));
        summary.put("encryption_overhead", encMetrics.get("overhead"));
        
        return summary;
    }
    
    private List<String> generateRecommendations(Map<String, Object> metrics) {
        List<String> recommendations = new ArrayList<>();
        
        // Get proxy metrics
        Map<String, Object> proxyMetrics = (Map<String, Object>) ((Map<String, Object>) metrics.get("detailed")).get("proxy_performance");
        double totalOverhead = (double) proxyMetrics.get("total_overhead");
        double latencyMs = (double) proxyMetrics.get("latency_ms");
        
        // Get encryption metrics
        Map<String, Object> encMetrics = (Map<String, Object>) ((Map<String, Object>) metrics.get("detailed")).get("encryption_performance");
        double encOverhead = (double) encMetrics.get("overhead");
        double encThroughput = (double) encMetrics.get("throughput_mb");
        
        // Proxy performance recommendations
        if (totalOverhead > 20) {
            recommendations.add("High proxy overhead detected. Consider optimizing request/response processing.");
        }
        if (latencyMs > 100) {
            recommendations.add("High proxy latency detected. Review network configuration and processing logic.");
        }
        
        // Encryption performance recommendations
        if (encOverhead > 15) {
            recommendations.add("High encryption overhead detected. Consider using more efficient algorithms or hardware acceleration.");
        }
        if (encThroughput < 10) {
            recommendations.add("Low encryption throughput. Consider optimizing encryption implementation or using faster algorithms.");
        }
        
        return recommendations;
    }
} 