package org.example.config;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.Map;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ProxyConfig {
    private static final Logger logger = LoggerFactory.getLogger(ProxyConfig.class);
    private static ProxyConfig instance;
    private final Properties properties = new Properties();

    // Default values
    private static final int DEFAULT_PORT = 8000;
    private static final int DEFAULT_MAX_RETRIES = 3;
    private static final long DEFAULT_RETRY_DELAY_MS = 1000;
    private static final String DEFAULT_GLUSTER_HOST = "92.168.10.234";
    private static final int DEFAULT_GLUSTER_PORT = 24007;
    private static final String DEFAULT_GLUSTER_VOLUME = "gv0";
    private static final String DEFAULT_MOUNT_POINT = "/data/gluster/gv0";
    private static final String DEFAULT_ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int DEFAULT_KEY_SIZE = 256;
    private static final int DEFAULT_LARGE_FILE_THRESHOLD = 1048576;
    private static final String DEFAULT_HDFS_NAMENODE_URL = "hdfs://localhost:9000";
    private static final String DEFAULT_HDFS_USER_NAME = "hadoop";
    private static final String DEFAULT_HDFS_BASE_PATH = "/user/hadoop/mitm-proxy";
    private static final int DEFAULT_HDFS_REPLICATION = 3;
    private static final long DEFAULT_HDFS_BLOCK_SIZE = 134217728;
    private static final String DEFAULT_HADOOP_HOME = "/opt/hadoop";
    private static final String DEFAULT_HDFS_CMD = "/opt/hadoop/bin/hdfs";

    @Value("${proxy.port:8080}")
    private int proxyPort;

    @Value("${proxy.host:localhost}")
    private String proxyHost;

    @Value("${storage.type:glusterfs}")
    private String storageType;

    @Value("${gluster.host:localhost}")
    private String glusterHost;

    @Value("${gluster.port:24007}")
    private int glusterPort;

    @Value("${gluster.volume:gv0}")
    private String glusterVolume;

    @Value("${gluster.mountPoint:/data/gluster/gv0}")
    private String glusterMountPoint;

    @Value("${hdfs.namenode.url:hdfs://localhost:9000}")
    private String hdfsNamenodeUrl;

    @Value("${hdfs.user.name:hadoop}")
    private String hdfsUserName;

    @Value("${hdfs.base.path:/user/hadoop/mitm-proxy}")
    private String hdfsBasePath;

    @Value("${hdfs.replication:3}")
    private int hdfsReplication;

    @Value("${hdfs.block.size:134217728}")
    private long hdfsBlockSize;

    @Value("${hadoop.home:/usr/local/hadoop}")
    private String hadoopHome;

    @Value("${hdfs.cmd:hdfs}")
    private String hdfsCmd;

    private ProxyConfig() {
        loadConfig();
    }

    public static ProxyConfig getInstance() {
        if (instance == null) {
            instance = new ProxyConfig();
        }
        return instance;
    }

    private void loadConfig() {
        // Load from proxy-config.properties
        try (FileInputStream fis = new FileInputStream("proxy-config.properties")) {
            properties.load(fis);
            logger.info("Configuration loaded from proxy-config.properties");
        } catch (IOException e) {
            logger.warn("Could not load proxy-config.properties, falling back to environment variables or defaults.", e);
        }

        // Load from .env file
        try (FileInputStream fis = new FileInputStream(".env")) {
            Properties envProps = new Properties();
            envProps.load(fis);
            for (String key : envProps.stringPropertyNames()) {
                properties.setProperty(key, envProps.getProperty(key));
                logger.debug("Loaded property from .env: {} = {}", key, envProps.getProperty(key));
            }
            logger.info("Configuration loaded from .env file");
        } catch (IOException e) {
            logger.warn("Could not load .env file, falling back to environment variables or defaults.", e);
        }
    }

    public void reload() {
        properties.clear();
        loadConfig();
    }
    

    // Utility to get config: ENV > properties > default
    private String get(String key, String defaultVal) {
        String envKey = key.toUpperCase().replace('.', '_');
        String envVal = System.getenv(envKey);
        return envVal != null ? envVal : properties.getProperty(key, defaultVal);
    }

    private int getInt(String key, int defaultVal) {
        return Integer.parseInt(get(key, String.valueOf(defaultVal)));
    }

    private long getLong(String key, long defaultVal) {
        return Long.parseLong(get(key, String.valueOf(defaultVal)));
    }

    // Proxy settings
    public int getProxyPort() {
        return proxyPort;
    }

    public String getProxyHost() {
        return proxyHost;
    }

    public String getStorageType() {
        return storageType;
    }

    public int getMaxRetries() {
        return getInt("proxy.max.retries", DEFAULT_MAX_RETRIES);
    }

    public long getRetryDelayMs() {
        return getLong("proxy.retry.delay.ms", DEFAULT_RETRY_DELAY_MS);
    }

    // GlusterFS settings
    public String getGlusterHost() {
        return glusterHost;
    }

    public int getGlusterPort() {
        return glusterPort;
    }

    public String getGlusterVolume() {
        return glusterVolume;
    }

    public String getGlusterMountPoint() {
        return glusterMountPoint;
    }

    // Vault settings
    public String getVaultAddress() {
        String address = get("vault.address", "http://localhost:8200");
        logger.info("Vault address from config: {}", address);
        return address;
    }

    public String getVaultAuthMethod() {
        return get("vault.authMethod", "token");
    }

    public String getVaultRoleId() {
        String role = get("vault.roleId", null);
        logger.info("Vault role ID from config: {}", role);
        return role; // Required
    }

    public String getVaultToken() {
        return get("vault.token", null);
    }

    public String getVaultKeyPath() {
        return get("vault.keyPath", "secret/data/encryption");
    }

    public String getVaultTransitPath() {
        return get("vault.transitPath", "transit/keys");
    }

    public String getVaultMetadataPath() {
        return get("vault.metadataPath", "secret/data/metadata");
    }

    public String getVaultAESKeyName() {
        return get("vault.aesKeyName", "aes-encryption-key");
    }

    public String getVaultChaChaKeyName() {
        return get("vault.chachaKeyName", "chacha-encryption-key");
    }

    // Encryption
    public String getEncryptionAlgorithm() {
        return get("encryption.algorithm", DEFAULT_ENCRYPTION_ALGORITHM);
    }

    public int getKeySize() {
        return getInt("encryption.key.size", DEFAULT_KEY_SIZE);
    }

    public int getLargeFileThreshold() {
        return getInt("encryption.largeFileThreshold", DEFAULT_LARGE_FILE_THRESHOLD);
    }

    // HDFS settings
    public String getHdfsNamenodeUrl() {
        return get("hdfs.namenode.url", DEFAULT_HDFS_NAMENODE_URL);
    }

    public String getHdfsUserName() {
        return get("hdfs.user.name", DEFAULT_HDFS_USER_NAME);
    }

    public int getHdfsReplication() {
        return getInt("hdfs.replication", DEFAULT_HDFS_REPLICATION);
    }

    public long getHdfsBlockSize() {
        return getLong("hdfs.block.size", DEFAULT_HDFS_BLOCK_SIZE);
    }

    // Remote HDFS settings
    public boolean isHdfsRemoteEnabled() {
        return Boolean.parseBoolean(get("hdfs.remote.enabled", "false"));
    }

    public String getHdfsRemoteHost() {
        return get("hdfs.remote.host", "");
    }

    public int getHdfsRemotePort() {
        return getInt("hdfs.remote.port", 22);
    }

    public String getHdfsRemoteUser() {
        return get("hdfs.remote.user", "");
    }

    public String getHdfsRemoteKeyPath() {
        return get("hdfs.remote.key.path", "");
    }

    public String getHdfsRemoteTempDir() {
        return get("hdfs.remote.temp.dir", "/tmp/mitm-proxy");
    }

    public String getHdfsNamenodeDir() {
        return get("hdfs.namenode.dir", "");
    }

    public String getHdfsDatanodeDir() {
        return get("hdfs.datanode.dir", "");
    }

    public void setStorageType(String type) {
        this.storageType = type;
    }

    public Map<String, Object> getStorageConfig() {
        Map<String, Object> config = new HashMap<>();
        
        if (storageType.equalsIgnoreCase("glusterfs")) {
            config.put("gluster.mountPoint", getGlusterMountPoint());
            config.put("gluster.host", getGlusterHost());
            config.put("gluster.volume", getGlusterVolume());
        } else if (storageType.equalsIgnoreCase("hdfs")) {
            config.put("hdfs.base.path", getHdfsBasePath());
            config.put("hdfs.namenode.url", getHdfsNamenodeUrl());
            config.put("hdfs.user.name", getHdfsUserName());
            config.put("hdfs.replication", getHdfsReplication());
            config.put("hdfs.block.size", getHdfsBlockSize());
            config.put("hdfs.remote.enabled", isHdfsRemoteEnabled());
            config.put("hdfs.remote.host", getHdfsRemoteHost());
            config.put("hdfs.remote.port", getHdfsRemotePort());
            config.put("hdfs.remote.user", getHdfsRemoteUser());
            config.put("hdfs.remote.key.path", getHdfsRemoteKeyPath());
            config.put("hdfs.remote.temp.dir", getHdfsRemoteTempDir());
        }
        
        return config;
    }

    public String getHdfsUri() {
        return properties.getProperty("hdfs.uri", "hdfs://localhost:9000");
    }

    public String getHdfsUser() {
        return properties.getProperty("hdfs.user", System.getProperty("user.name"));
    }

    public String getHdfsBasePath() {
        return properties.getProperty("hdfs.base.path", "/user/" + getHdfsUser() + "/mitm-proxy");
    }

    public String getHadoopHome() {
        return get("hadoop.home", DEFAULT_HADOOP_HOME);
    }

    public String getHdfsCmd() {
        return get("hdfs.cmd", DEFAULT_HDFS_CMD);
    }
}
