#!/bin/bash

# Exit on error and print each command
set -e
set -x

# === Configuration ===
GLUSTER_NODES=("172.30.6.144" "172.30.6.173")
PROXY_HOST="172.30.6.61"
OBSERVER_PORT="8081"
AGENT_DIR="/opt/gluster_agent"
SSH_KEY="/home/ubuntu/.ssh/gluster_key"

# === Install Dependencies ===
install_dependencies() {
    local node=$1
    ssh -i "$SSH_KEY" ubuntu@$node "sudo apt-get update && sudo apt-get install -y gcc libjansson-dev libssl-dev make"
}

# === Deploy Agent ===
deploy_agent() {
    local node=$1
    echo "Deploying agent to $node..."

    # Create install directory
    ssh -i "$SSH_KEY" ubuntu@$node "sudo mkdir -p $AGENT_DIR && sudo chown ubuntu:ubuntu $AGENT_DIR"

    # Copy source files
    scp -i "$SSH_KEY" agent/agent.c ubuntu@$node:$AGENT_DIR/
    scp -i "$SSH_KEY" agent/Makefile ubuntu@$node:$AGENT_DIR/

    # Compile agent
    ssh -i "$SSH_KEY" ubuntu@$node "cd $AGENT_DIR && make"

    # Create local systemd service file
    cat > gluster_agent.service <<EOF
[Unit]
Description=GlusterFS Security Agent
After=network.target

[Service]
Type=simple
ExecStart=$AGENT_DIR/gluster_agent $PROXY_HOST $OBSERVER_PORT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Copy and enable the service
    scp -i "$SSH_KEY" gluster_agent.service ubuntu@$node:/tmp/
    ssh -i "$SSH_KEY" ubuntu@$node "sudo mv /tmp/gluster_agent.service /etc/systemd/system/"
    ssh -i "$SSH_KEY" ubuntu@$node "sudo systemctl daemon-reload && sudo systemctl enable gluster_agent && sudo systemctl restart gluster_agent"

    # Clean up local service file
    rm gluster_agent.service
}

# === Main Process ===
for node in "${GLUSTER_NODES[@]}"; do
    echo "Processing node: $node"
    install_dependencies "$node"
    deploy_agent "$node"
    echo "Agent deployed successfully on $node"
done

echo "Agent deployment completed on all nodes."
