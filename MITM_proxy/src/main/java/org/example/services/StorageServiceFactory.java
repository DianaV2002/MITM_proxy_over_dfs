package org.example.services;

import org.example.config.ProxyConfig;
import org.springframework.stereotype.Component;

import java.rmi.Remote;
import java.util.Map;

@Component
public class StorageServiceFactory {
    private final GlusterFSNFSService glusterService;
    private final RemoteHDFSService hdfsService;
    private final ProxyConfig proxyConfig;

    public StorageServiceFactory(GlusterFSNFSService glusterService, 
                               RemoteHDFSService hdfsService,
                               ProxyConfig proxyConfig) {
        this.glusterService = glusterService;
        this.hdfsService = hdfsService;
        this.proxyConfig = proxyConfig;
    }

    public StorageService getStorageService() {
        String storageType = proxyConfig.getStorageType();
        
        switch (storageType.toLowerCase()) {
            case "glusterfs":
                return glusterService;
            case "hdfs":
                return hdfsService;
            default:
                throw new IllegalArgumentException("Unsupported storage type: " + storageType);
        }
    }

    public void initializeStorageService(Map<String, Object> config) {
        StorageService service = getStorageService();
        service.initialize(config);
    }
} 