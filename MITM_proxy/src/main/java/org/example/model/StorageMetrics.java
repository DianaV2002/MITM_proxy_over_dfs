package org.example.model;

import java.util.Objects;

public class StorageMetrics {
    private long totalSpace;
    private long usedSpace;
    private long freeSpace;
    private double cpuUsage;
    private double memoryUsage;
    private double networkThroughput;
    private double diskLatency;
    private int activeConnections;
    private long timestamp;

    public StorageMetrics() {
        this.timestamp = System.currentTimeMillis();
    }

    public long getTotalSpace() {
        return totalSpace;
    }

    public void setTotalSpace(long totalSpace) {
        this.totalSpace = totalSpace;
    }

    public long getUsedSpace() {
        return usedSpace;
    }

    public void setUsedSpace(long usedSpace) {
        this.usedSpace = usedSpace;
    }

    public long getFreeSpace() {
        return freeSpace;
    }

    public void setFreeSpace(long freeSpace) {
        this.freeSpace = freeSpace;
    }

    public double getCpuUsage() {
        return cpuUsage;
    }

    public void setCpuUsage(double cpuUsage) {
        this.cpuUsage = cpuUsage;
    }

    public double getMemoryUsage() {
        return memoryUsage;
    }

    public void setMemoryUsage(double memoryUsage) {
        this.memoryUsage = memoryUsage;
    }

    public double getNetworkThroughput() {
        return networkThroughput;
    }

    public void setNetworkThroughput(double networkThroughput) {
        this.networkThroughput = networkThroughput;
    }

    public double getDiskLatency() {
        return diskLatency;
    }

    public void setDiskLatency(double diskLatency) {
        this.diskLatency = diskLatency;
    }

    public int getActiveConnections() {
        return activeConnections;
    }

    public void setActiveConnections(int activeConnections) {
        this.activeConnections = activeConnections;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StorageMetrics that = (StorageMetrics) o;
        return totalSpace == that.totalSpace &&
                usedSpace == that.usedSpace &&
                freeSpace == that.freeSpace &&
                Double.compare(that.cpuUsage, cpuUsage) == 0 &&
                Double.compare(that.memoryUsage, memoryUsage) == 0 &&
                Double.compare(that.networkThroughput, networkThroughput) == 0 &&
                Double.compare(that.diskLatency, diskLatency) == 0 &&
                activeConnections == that.activeConnections &&
                timestamp == that.timestamp;
    }

    @Override
    public int hashCode() {
        return Objects.hash(totalSpace, usedSpace, freeSpace, cpuUsage, memoryUsage, 
                          networkThroughput, diskLatency, activeConnections, timestamp);
    }

    @Override
    public String toString() {
        return "StorageMetrics{" +
                "totalSpace=" + totalSpace +
                ", usedSpace=" + usedSpace +
                ", freeSpace=" + freeSpace +
                ", cpuUsage=" + cpuUsage +
                ", memoryUsage=" + memoryUsage +
                ", networkThroughput=" + networkThroughput +
                ", diskLatency=" + diskLatency +
                ", activeConnections=" + activeConnections +
                ", timestamp=" + timestamp +
                '}';
    }
} 