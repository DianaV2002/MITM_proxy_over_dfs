package org.example.services;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.Map;

import org.example.entities.FileInfo;

public interface StorageService {
    /**
     * Initialize the storage service with configuration
     * @param config Configuration map
     */
    void initialize(Map<String, Object> config);

    /**
     * Store a file in the storage system
     * @param inputStream The input stream containing the file data
     * @param fileName The name of the file
     * @param fileSize The size of the file
     * @param metadata Additional metadata about the file
     * @return The file ID
     */
    String storeFile(InputStream inputStream, String fileName, long fileSize, Map<String, Object> metadata);

    /**
     * Retrieve a file from the storage system
     * @param fileId The ID of the file to retrieve
     * @return The file content as an InputStream
     */
    InputStream retrieveFile(String fileId);

    /**
     * Delete a file from the storage system
     * @param fileId The ID of the file to delete
     * @return true if deletion was successful, false otherwise
     */
    boolean deleteFile(String fileId);

    /**
     * Get performance metrics
     * @return Map of performance metrics
     */
    Map<String, Object> getMetrics();

    /**
     * Clear performance metrics
     */
    void clearMetrics();

    /**
     * Retrieve a file as bytes from the storage system
     * @param fileId The ID of the file to retrieve
     * @return The file content as bytes
     */
    byte[] retrieveFileAsBytes(String fileId);

    /**
     * List all files in the storage system
     * @return List of file information
     */
    List<FileInfo> listFiles();

    /**
     * Get the file path for a given file ID
     * @param fileId The ID of the file
     * @return The path to the file
     */
    String getFilePath(String fileId);

    /**
     * Store a file using streaming
     * @param fileId The ID of the file
     * @param inputStream The input stream containing the file data
     * @return true if storage was successful, false otherwise
     */
    boolean storeFileStreaming(String fileId, InputStream inputStream);

    /**
     * Clean up resources
     */
    void cleanup();

    /**
     * Create an output stream for writing to storage
     * @param fileId The ID of the file
     * @return An output stream for writing
     */
    OutputStream createStorageOutputStream(String fileId);
} 