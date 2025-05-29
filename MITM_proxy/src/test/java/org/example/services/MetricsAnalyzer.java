package org.example.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.File;
import java.util.*;

public class MetricsAnalyzer {
    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode report = mapper.readTree(new File("test-files/comparison_report.json"));
        
        System.out.println("=== Storage Service Comparison Metrics ===\n");
        
        for (JsonNode fileResult : report) {
            String filename = fileResult.get("file").asText();
            long sizeBytes = fileResult.get("size_bytes").asLong();
            
            System.out.printf("\nFile: %s (%.2f MB)\n", filename, sizeBytes / (1024.0 * 1024.0));
            System.out.println("----------------------------------------");
            
            // GlusterFS Metrics
            JsonNode glusterUpload = fileResult.get("gluster_upload_metrics");
            JsonNode glusterDownload = fileResult.get("gluster_download_metrics");
            String glusterAlg = fileResult.get("gluster_algorithm").asText();
            
            System.out.println("\nGlusterFS:");
            System.out.printf("Encryption Algorithm: %s\n", glusterAlg);
            System.out.printf("Upload Time: %.2f ms\n", glusterUpload.get("total_encryption_time_ms").asDouble());
            System.out.printf("Upload Throughput: %.2f MB/s\n", 
                calculateThroughput(sizeBytes, glusterUpload.get("total_encryption_time_ms").asDouble()));
            System.out.printf("Memory Usage: %.2f MB\n", 
                parseMemoryUsage(glusterUpload.get("memory_usage").asText()));
            System.out.printf("CPU Usage: %.1f%%\n", 
                parseCPUUsage(glusterUpload.get("cpu_usage").asText()));
            
            // HDFS Metrics
            JsonNode hdfsUpload = fileResult.get("hdfs_upload_metrics");
            JsonNode hdfsDownload = fileResult.get("hdfs_download_metrics");
            String hdfsAlg = fileResult.get("hdfs_algorithm").asText();
            
            System.out.println("\nHDFS:");
            System.out.printf("Encryption Algorithm: %s\n", hdfsAlg);
            System.out.printf("Upload Time: %.2f ms\n", hdfsUpload.get("total_encryption_time_ms").asDouble());
            System.out.printf("Upload Throughput: %.2f MB/s\n", 
                calculateThroughput(sizeBytes, hdfsUpload.get("total_encryption_time_ms").asDouble()));
            System.out.printf("Memory Usage: %.2f MB\n", 
                parseMemoryUsage(hdfsUpload.get("memory_usage").asText()));
            System.out.printf("CPU Usage: %.1f%%\n", 
                parseCPUUsage(hdfsUpload.get("cpu_usage").asText()));
            
            // Comparison Summary
            System.out.println("\nComparison Summary:");
            double glusterTime = glusterUpload.get("total_encryption_time_ms").asDouble();
            double hdfsTime = hdfsUpload.get("total_encryption_time_ms").asDouble();
            System.out.printf("Performance Ratio (HDFS/GlusterFS): %.2fx\n", hdfsTime / glusterTime);
            System.out.println("----------------------------------------");
        }
    }
    
    private static double calculateThroughput(long bytes, double ms) {
        return (bytes / (1024.0 * 1024.0)) / (ms / 1000.0);
    }
    
    private static double parseMemoryUsage(String memoryStr) {
        try {
            return Double.parseDouble(memoryStr);
        } catch (Exception e) {
            return 0.0;
        }
    }
    
    private static double parseCPUUsage(String cpuStr) {
        try {
            return Double.parseDouble(cpuStr);
        } catch (Exception e) {
            return 0.0;
        }
    }
} 