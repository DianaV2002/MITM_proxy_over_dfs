package org.example.services;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class StorageServiceComparisonTest {
    private static final String TEST_DIR = "test-files";
    private static final ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final List<String> TEST_FILES = Arrays.asList(
        "tiny.txt",    // 10 bytes
        "small.txt",   // 1 KB
        "medium.txt",  // 100 KB
        "large.bin"    // 6 MB
    );

    @BeforeAll
    public static void setup() throws Exception {
        // Ensure test directory exists
        Files.createDirectories(Paths.get(TEST_DIR));
    }

    @Test
    public void compareStorageServices() throws Exception {
        List<Map<String, Object>> results = new ArrayList<>();
        GlusterFSNFSService glusterService = TestServiceFactory.createGlusterFSNFSService();
        RemoteHDFSService hdfsService = TestServiceFactory.createRemoteHDFSService();

        for (String filename : TEST_FILES) {
            Path filePath = Paths.get(TEST_DIR, filename);
            if (!Files.exists(filePath)) {
                System.out.println("Skipping " + filename + " - file not found");
                continue;
            }

            Map<String, Object> result = new HashMap<>();
            result.put("file", filename);
            result.put("size_bytes", Files.size(filePath));

            // Test GlusterFS
            System.out.println("Testing GlusterFS with " + filename);
            String glusterFileId = glusterService.storeFile(Files.newInputStream(filePath), filename, Files.size(filePath), new HashMap<>());
            result.put("gluster_upload_metrics", glusterService.getMetrics());
            result.put("gluster_algorithm", getAlgorithmFromMetadata(glusterService, glusterFileId));
            
            Path glusterDownloadPath = Paths.get(TEST_DIR, "gluster_" + filename);
            try (var inputStream = glusterService.retrieveFile(glusterFileId)) {
                Files.copy(inputStream, glusterDownloadPath);
            }
            result.put("gluster_download_metrics", glusterService.getMetrics());
            Files.deleteIfExists(glusterDownloadPath);

            // Test HDFS
            System.out.println("Testing HDFS with " + filename);
            String hdfsFileId = hdfsService.storeFile(Files.newInputStream(filePath), filename, Files.size(filePath), new HashMap<>());
            result.put("hdfs_upload_metrics", hdfsService.getMetrics());
            result.put("hdfs_algorithm", getAlgorithmFromMetadata(hdfsService, hdfsFileId));
            
            Path hdfsDownloadPath = Paths.get(TEST_DIR, "hdfs_" + filename);
            try (var inputStream = hdfsService.retrieveFile(hdfsFileId)) {
                Files.copy(inputStream, hdfsDownloadPath);
            }
            result.put("hdfs_download_metrics", hdfsService.getMetrics());
            Files.deleteIfExists(hdfsDownloadPath);

            results.add(result);
        }

        // Write comparison report
        File reportFile = new File(TEST_DIR, "comparison_report.json");
        mapper.writeValue(reportFile, results);
        System.out.println("Comparison report written to: " + reportFile.getAbsolutePath());
    }

    private String getAlgorithmFromMetadata(StorageService service, String fileId) {
        try {
            Map<String, Object> metadata = service instanceof GlusterFSNFSService
                ? ((GlusterFSNFSService)service).getVaultService().getMetadata(fileId)
                : ((RemoteHDFSService)service).getVaultService().getMetadata(fileId);
            return metadata != null ? String.valueOf(metadata.get("algorithm")) : "unknown";
        } catch (Exception e) {
            return "unknown";
        }
    }
} 