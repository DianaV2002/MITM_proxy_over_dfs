package org.example.config;

import org.example.services.StorageService;
import org.example.services.GlusterFSNFSService;
import org.example.services.MetricsServiceImpl;
import org.example.services.PerformanceMetricsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Configuration
public class StorageConfig {
    
    @Bean
    @Primary
    public StorageService storageService(MetricsServiceImpl metricsService, PerformanceMetricsService performanceMetrics) {
        return new GlusterFSNFSService(metricsService, performanceMetrics);
    }
} 