#!/bin/bash

JAR_NAME="netty-proxy-1.0-SNAPSHOT.jar"
JAR_PATH="target/${JAR_NAME}"
LOG_DIR="/var/log/gluster_observer"
PID_FILE="/var/run/gluster_observer.pid"

mkdir -p "$LOG_DIR"

# Check if Observer is already running
if [ -f "$PID_FILE" ] && ps -p $(cat "$PID_FILE") > /dev/null 2>&1; then
    echo "Observer is already running with PID $(cat "$PID_FILE")."
    exit 0
fi

# Build the project if the JAR is missing
if [ ! -f "$JAR_PATH" ]; then
    echo "Observer JAR not found. Building with Maven using 'observer' profile..."
    mvn clean package -DskipTests -Pobserver || { echo "Build failed."; exit 1; }
fi

echo "Starting Observer..."
nohup java -jar "$JAR_PATH" > "$LOG_DIR/observer.out" 2>&1 &
echo $! > "$PID_FILE"

echo "Observer started on PID $(cat "$PID_FILE"). Logs: $LOG_DIR/observer.out"
