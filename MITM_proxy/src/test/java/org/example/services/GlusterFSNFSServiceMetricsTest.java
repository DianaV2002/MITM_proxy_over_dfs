package org.example.services;

import org.junit.jupiter.api.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class GlusterFSNFSServiceMetricsTest {
    private static final String TEST_DIR = "./test-files";
    private static final String REPORT_FILE = TEST_DIR + "/metrics_report.json";
    private GlusterFSNFSService service;
    private List<Map<String, Object>> reportRows = new ArrayList<>();

    @BeforeAll
    void setup() throws Exception {
        // Create test directory
        Files.createDirectories(Paths.get(TEST_DIR));
        // Create sample files
        createSampleFile("small.txt", 1024); // 1 KB
        createSampleFile("medium.txt", 1024 * 100); // 100 KB
        createSampleFile("large.bin", 1024 * 1024 * 6); // 2 MB
        createSampleFile("tiny.txt", 10); // 10 bytes
        // You can add more file types as needed
        // Initialize service (use mocks or real dependencies as needed)
        service = TestServiceFactory.createGlusterFSNFSService();
    }

    @Test
    void testFileOperationsAndMetrics() throws Exception {
        Files.list(Paths.get(TEST_DIR))
            .filter(Files::isRegularFile)
            .filter(p -> !p.getFileName().toString().equals("metrics_report.json"))
            .forEach(path -> {
                try {
                    String fileName = path.getFileName().toString();
                    long fileSize = Files.size(path);
                    // Upload
                    try (InputStream in = Files.newInputStream(path)) {
                        String fileId = service.storeFile(in, fileName, fileSize, new HashMap<>());
                        Map<String, Object> uploadMetrics = service.getMetrics();
                        // Download
                        try (InputStream download = service.retrieveFile(fileId)) {
                            while (download.read() != -1) {} // consume
                        }
                        Map<String, Object> downloadMetrics = service.getMetrics();
                        // Record
                        Map<String, Object> row = new LinkedHashMap<>();
                        row.put("file", fileName);
                        row.put("size_bytes", fileSize);
                        row.put("upload_metrics", uploadMetrics);
                        row.put("download_metrics", downloadMetrics);
                        reportRows.add(row);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
    }

    @AfterAll
    void writeReport() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.writerWithDefaultPrettyPrinter().writeValue(new File(REPORT_FILE), reportRows);
        System.out.println("Metrics report written to: " + REPORT_FILE);
    }

    private void createSampleFile(String name, int size) throws IOException {
        Path path = Paths.get(TEST_DIR, name);
        byte[] data = new byte[size];
        new Random().nextBytes(data);
        Files.write(path, data);
    }
}

// You will need to implement TestServiceFactory.createGlusterFSNFSService() to provide a testable instance. 