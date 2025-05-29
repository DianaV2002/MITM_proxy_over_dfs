package org.example.services;

import org.example.config.ProxyConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VaultTokenRefresher implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(VaultTokenRefresher.class);
    private final VaultService vaultService;
    private final int refreshIntervalSeconds;
    private final ProxyConfig config;

    public VaultTokenRefresher(VaultService vaultService, int refreshIntervalSeconds) {
        this.vaultService = vaultService;
        this.refreshIntervalSeconds = refreshIntervalSeconds;
        this.config = ProxyConfig.getInstance();
    }

    @Override
    public void run() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                String roleId = config.getVaultRoleId();
                if (roleId == null || roleId.trim().isEmpty()) {
                    logger.error("Vault role ID is not configured");
                    Thread.sleep(60000); // Wait 1 minute before retrying
                    continue;
                }

                String generatedSecretId = vaultService.generateSecretId();
                vaultService.authenticateWithAppRole(roleId, generatedSecretId);
                logger.info("Successfully refreshed Vault token");
                Thread.sleep(refreshIntervalSeconds * 1000L); // Convert seconds to milliseconds
            } catch (InterruptedException e) {
                logger.info("Vault token refresher thread interrupted");
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                logger.error("Error refreshing Vault token", e);
                // Wait a bit before retrying on error
                try {
                    Thread.sleep(60000); // Wait 1 minute before retrying on error
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }
} 