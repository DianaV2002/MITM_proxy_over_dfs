package org.example.services;

import org.example.config.ProxyConfig;

public class TestServiceFactory {
    public static GlusterFSNFSService createGlusterFSNFSService() {
        // Use simple in-memory or default implementations for dependencies
        MetricsServiceImpl metricsService = new MetricsServiceImpl();
        PerformanceMetricsService performanceMetrics = new PerformanceMetricsService();
        return new GlusterFSNFSService(metricsService, performanceMetrics);
    }

    public static RemoteHDFSService createRemoteHDFSService() {
        MetricsServiceImpl metricsService = new MetricsServiceImpl();
        PerformanceMetricsService performanceMetrics = new PerformanceMetricsService();
        return new RemoteHDFSService(metricsService, performanceMetrics);
    }

    // If you ever need to create HDFSService directly for tests:
    public static HDFSService createHDFSService() {
        MetricsServiceImpl metricsService = new MetricsServiceImpl();
        PerformanceMetricsService performanceMetrics = new PerformanceMetricsService();
        ProxyConfig proxyConfig = ProxyConfig.getInstance();
        return new HDFSService(proxyConfig, metricsService, performanceMetrics);
    }
} 