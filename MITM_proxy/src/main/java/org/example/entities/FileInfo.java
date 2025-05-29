package org.example.entities;

import java.time.Instant;

public class FileInfo {
    private final String name;
    private final long size;
    private final Instant lastModified;
    private final boolean isDirectory;

    public FileInfo(String name, long size, Instant lastModified, boolean isDirectory) {
        this.name = name;
        this.size = size;
        this.lastModified = lastModified;
        this.isDirectory = isDirectory;
    }

    public String getName() {
        return name;
    }

    public long getSize() {
        return size;
    }

    public Instant getLastModified() {
        return lastModified;
    }

    public boolean isDirectory() {
        return isDirectory;
    }

    @Override
    public String toString() {
        return String.format("FileInfo{name='%s', size=%d, lastModified=%s, isDirectory=%b}",
            name, size, lastModified, isDirectory);
    }
} 