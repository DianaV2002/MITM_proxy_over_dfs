package org.example.controllers;

import org.example.services.GlusterFSNFSService;
import org.example.services.VaultService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

@Controller
@RequestMapping("/visualization")
public class VisualizationController {
    private final Map<String, List<PerformanceMetric>> performanceHistory = new HashMap<>();
    private int totalOperations = 0;
    private long totalTime = 0;
    private int successfulOperations = 0;

    @Autowired
    private GlusterFSNFSService glusterService;

    @Autowired
    private VaultService vaultService;

    @GetMapping
    public String index(Model model) {
        // Get metrics from GlusterFS service
        Map<String, Object> metrics = glusterService.getMetrics();
        
        // Add general metrics
        model.addAttribute("totalOperations", metrics.getOrDefault("total_operations", 0));
        model.addAttribute("averageTime", metrics.getOrDefault("average_time", 0.0));
        model.addAttribute("successRate", metrics.getOrDefault("success_rate", 0.0));
        
        // Add GlusterFS metrics
        model.addAttribute("metrics", metrics);
        
        // Add encryption visualization data
        Map<String, Object> visualization = new HashMap<>();
        
        // Process flow visualization
        List<Map<String, Object>> steps = new ArrayList<>();
        
        // Step 1: File Upload
        Map<String, Object> uploadStep = new HashMap<>();
        uploadStep.put("step", 1);
        uploadStep.put("name", "File Upload");
        uploadStep.put("status", "completed");
        uploadStep.put("details", "Ready to process files");
        steps.add(uploadStep);
        
        // Step 2: First Layer Encryption
        Map<String, Object> firstEncStep = new HashMap<>();
        firstEncStep.put("step", 2);
        firstEncStep.put("name", "First Layer Encryption");
        firstEncStep.put("status", "completed");
        firstEncStep.put("details", "Using dynamic algorithm selection");
        steps.add(firstEncStep);
        
        // Step 3: Second Layer Encryption
        Map<String, Object> secondEncStep = new HashMap<>();
        secondEncStep.put("step", 3);
        secondEncStep.put("name", "Second Layer Encryption");
        secondEncStep.put("status", "completed");
        secondEncStep.put("details", "Additional security layer");
        steps.add(secondEncStep);
        
        // Step 4: Storage
        Map<String, Object> storageStep = new HashMap<>();
        storageStep.put("step", 4);
        storageStep.put("name", "Secure Storage");
        storageStep.put("status", "completed");
        storageStep.put("details", "File stored in GlusterFS with metadata in Vault");
        steps.add(storageStep);
        
        visualization.put("steps", steps);
        
        // Performance metrics
        Map<String, Object> performance = new HashMap<>();
        performance.put("compressionRatio", "0.00%");
        performance.put("totalEncryptionTime", metrics.getOrDefault("total_encryption_time", 0));
        performance.put("originalSize", metrics.getOrDefault("data_processed", 0));
        performance.put("finalSize", metrics.getOrDefault("data_written", 0));
        visualization.put("performance", performance);
        
        // Security status
        Map<String, Object> security = new HashMap<>();
        security.put("algorithm", "Dynamic");
        security.put("keyVersion", "1");
        security.put("encryptionStatus", "success");
        security.put("layers", 2);
        visualization.put("security", security);
        
        model.addAttribute("visualization", visualization);
        
        return "visualization";
    }

    @PostMapping("/api/performance")
    @ResponseBody
    public Map<String, Object> recordPerformance(@RequestBody PerformanceMetric metric) {
        Map<String, Object> response = new HashMap<>();
        try {
            totalOperations++;
            totalTime += metric.getTime();
            if (metric.isSuccess()) {
                successfulOperations++;
            }
            
            performanceHistory.computeIfAbsent(metric.getMethod(), k -> new ArrayList<>())
                            .add(metric);
            
            response.put("success", true);
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", e.getMessage());
        }
        return response;
    }

    @GetMapping("/api/performance")
    @ResponseBody
    public Map<String, Object> getPerformanceMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        // Get metrics from GlusterFS service
        Map<String, Object> glusterMetrics = glusterService.getMetrics();
        if (glusterMetrics != null) {
            metrics.putAll(glusterMetrics);
        }
        
        // Ensure all required metrics are present and properly formatted
        metrics.put("proxy_latency", formatMetric(metrics.get("proxy_latency"), 0.0));
        metrics.put("request_time", formatMetric(metrics.get("request_time"), 0.0));
        metrics.put("response_time", formatMetric(metrics.get("response_time"), 0.0));
        metrics.put("proxy_overhead", formatMetric(metrics.get("proxy_overhead"), 0.0));
        metrics.put("encryption_throughput", formatMetric(metrics.get("encryption_throughput"), 0.0));
        metrics.put("decryption_throughput", formatMetric(metrics.get("decryption_throughput"), 0.0));
        metrics.put("total_operations", formatMetric(metrics.get("total_operations"), 0));
        metrics.put("average_time", formatMetric(metrics.get("average_time"), 0.0));
        metrics.put("success_rate", formatMetric(metrics.get("success_rate"), 0.0));
        metrics.put("data_processed", formatMetric(metrics.get("data_processed"), 0.0));
        
        // Add system metrics
        metrics.put("cpu_usage", formatMetric(metrics.get("cpu_usage"), 0.0));
        metrics.put("memory_usage", formatMetric(metrics.get("memory_usage"), 0.0));
        metrics.put("non_heap_memory_mb", formatMetric(metrics.get("non_heap_memory_mb"), 0.0));
        
        return metrics;
    }
    
    private Object formatMetric(Object value, Object defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        try {
            if (value instanceof Number) {
                if (value instanceof Integer || value instanceof Long) {
                    return value;
                }
                return String.format("%.2f", ((Number) value).doubleValue());
            } else if (value instanceof String) {
                try {
                    return String.format("%.2f", Double.parseDouble((String) value));
                } catch (NumberFormatException e) {
                    return defaultValue;
                }
            }
            return defaultValue;
        } catch (Exception e) {
            return defaultValue;
        }
    }

    @GetMapping("/api/vault-token-ttl")
    @ResponseBody
    public Map<String, Object> getVaultTokenTTL() {
        Map<String, Object> response = new HashMap<>();
        try {
            long ttl = vaultService.getTokenTTL();
            response.put("ttl", ttl);
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    @PostMapping("/api/clear")
    @ResponseBody
    public Map<String, Object> clearMetrics() {
        glusterService.clearMetrics();
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "Metrics cleared successfully");
        return response;
    }

    public static class PerformanceMetric {
        private String method;
        private long time;
        private long size;
        private boolean success;

        public String getMethod() { return method; }
        public void setMethod(String method) { this.method = method; }
        public long getTime() { return time; }
        public void setTime(long time) { this.time = time; }
        public long getSize() { return size; }
        public void setSize(long size) { this.size = size; }
        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public double getSpeed() { return (double) size / time; }
    }
} 