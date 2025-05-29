#!/bin/bash

# Create necessary directories
sudo mkdir -p /hadoop/hdfs/namenode
sudo mkdir -p /hadoop/hdfs/datanode
sudo mkdir -p /hadoop/tmp

# Set permissions
sudo chown -R hadoop:hadoop /hadoop
sudo chmod -R 755 /hadoop

# Format HDFS
hdfs namenode -format

# Start HDFS services
start-dfs.sh

# Create required HDFS directories
hdfs dfs -mkdir -p /user/hadoop
hdfs dfs -chown hadoop:hadoop /user/hadoop

# Verify HDFS is running
hdfs dfsadmin -report

echo "HDFS setup completed. You can access the web interface at:"
echo "Namenode: http://localhost:9870"
echo "Datanode: http://localhost:9864" 