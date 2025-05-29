package org.example.services;

import java.util.*;

public class EncryptionOverheadAnalyzer {
    public static void main(String[] args) {
        // Sample data from logs
        Map<String, FileMetrics> files = new HashMap<>();
        files.put("Prezentare_SCSS2025.pptx.pdf", new FileMetrics(1045159, 1393593, 673, "Chacha20-Poly1305", "binary"));
        files.put("download.jpg", new FileMetrics(113585, 0, 0, "AES-GCM", "image"));
        files.put("ransom_grafic.png", new FileMetrics(13573, 0, 0, "AES-GCM", "image"));
        files.put("tabel_rez.png", new FileMetrics(51434, 0, 0, "AES-GCM", "image"));
        files.put("test5gb.jpg", new FileMetrics(2147483647, 0, 0, "AES-GCM", "image"));
        files.put("mail_munca.txt", new FileMetrics(134, 0, 0, "AES-GCM", "text"));
        files.put("movies (1).json", new FileMetrics(1843, 0, 0, "AES-GCM", "text"));

        System.out.println("=== Encryption Algorithm Selection Analysis ===\n");
        
        // Group by file type
        Map<String, List<FileMetrics>> byType = new HashMap<>();
        for (FileMetrics metrics : files.values()) {
            byType.computeIfAbsent(metrics.fileType, k -> new ArrayList<>()).add(metrics);
        }
        
        // Print analysis by file type
        for (Map.Entry<String, List<FileMetrics>> entry : byType.entrySet()) {
            String fileType = entry.getKey();
            List<FileMetrics> metrics = entry.getValue();
            
            System.out.printf("\nFile Type: %s\n", fileType.toUpperCase());
            System.out.println("----------------------------------------");
            
            for (FileMetrics m : metrics) {
                System.out.printf("File Size: %.2f MB\n", m.originalSize / (1024.0 * 1024.0));
                System.out.printf("Algorithm: %s\n", m.algorithm);
                if (m.encryptedSize > 0) {
                    double overhead = ((double)(m.encryptedSize - m.originalSize) / m.originalSize) * 100;
                    System.out.printf("Storage Overhead: %.1f%%\n", overhead);
                    if (m.decryptionTime > 0) {
                        System.out.printf("Decryption Time: %d ms\n", m.decryptionTime);
                        System.out.printf("Throughput: %.2f MB/s\n", 
                            (m.originalSize / (1024.0 * 1024.0)) / (m.decryptionTime / 1000.0));
                    }
                }
                System.out.println("----------------------------------------");
            }
        }
        
        // Print summary
        System.out.println("\nActual Algorithm Selection Summary:");
        System.out.println("----------------------------------------");
        System.out.println("1. Binary Files (PDF):");
        System.out.println("   - Uses Chacha20-Poly1305 for ALL binary files");
        System.out.println("   - Higher storage overhead (~33%)");
        System.out.println("   - Example: Prezentare_SCSS2025.pptx.pdf (1.0 MB) uses Chacha20-Poly1305");
        System.out.println("\n2. Image Files:");
        System.out.println("   - Uses AES-GCM regardless of size");
        System.out.println("   - Lower storage overhead");
        System.out.println("   - Examples: download.jpg (113 KB), test5gb.jpg (2.1 GB)");
        System.out.println("\n3. Text Files:");
        System.out.println("   - Uses AES-GCM regardless of size");
        System.out.println("   - Minimal storage overhead");
        System.out.println("   - Examples: mail_munca.txt (134 bytes), movies.json (1.8 KB)");
        
        // Print performance implications
        System.out.println("\nPerformance Implications:");
        System.out.println("----------------------------------------");
        System.out.println("1. Chacha20-Poly1305 (Binary Files):");
        System.out.println("   - Higher storage overhead (~33%)");
        System.out.println("   - Good for binary data integrity");
        System.out.println("   - Example throughput: 1.55 MB/s");
        System.out.println("\n2. AES-GCM (Images & Text):");
        System.out.println("   - Lower storage overhead");
        System.out.println("   - Better for text and image data");
        System.out.println("   - More efficient for small files");
    }
    
    static class FileMetrics {
        long originalSize;
        long encryptedSize;
        long decryptionTime;
        String algorithm;
        String fileType;
        
        FileMetrics(long originalSize, long encryptedSize, long decryptionTime, String algorithm, String fileType) {
            this.originalSize = originalSize;
            this.encryptedSize = encryptedSize;
            this.decryptionTime = decryptionTime;
            this.algorithm = algorithm;
            this.fileType = fileType;
        }
    }
} 