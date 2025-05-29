// Updated Observer Java Code with Protocol Fixes
package org.example.observer;

import java.io.*;
import java.net.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;

public class AgentListener implements Runnable {
    private int port;
    private ObjectMapper mapper = new ObjectMapper();
    private static final String SHARED_SECRET = "gluster_security_key_2024";
    private Random random = new Random();

    public AgentListener(int port) {
        this.port = port;
    }

    @Override
    public void run() {
        try (ServerSocket server = new ServerSocket(port)) {
            System.out.println("AgentListener started on port " + port);
            while (true) {
                Socket client = server.accept();
                handleClient(client);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void handleClient(Socket client) {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(client.getOutputStream()))
        ) {
            // Set socket timeout to prevent hanging indefinitely
            client.setSoTimeout(5000);

            String msg = in.readLine();
            System.out.println(">> Raw input line: " + msg);
            if (msg == null || msg.trim().isEmpty()) {
                System.err.println("Received empty message from client.");
                return;
            }

            System.out.println("Received message: " + msg);
            AgentPing ping = mapper.readValue(msg, AgentPing.class);

            System.out.println("Received from " + ping.node_id + ": " + ping.fd_count);

            AgentResponse resp = decideAction(ping);
            String responseJson = mapper.writeValueAsString(resp);
            System.out.println("Sending response: " + responseJson);

            // Send response with newline and flush to ensure delivery
            out.write(responseJson);
            out.newLine();
            out.flush();

            System.out.println("Sent response - Action: " + resp.action +
                               ", PID: " + resp.pid +
                               ", Challenge: " + resp.challenge);

        } catch (Exception e) {
            System.err.println("Error handling client: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                client.close();
            } catch (IOException ex) {
                System.err.println("Error closing client socket: " + ex.getMessage());
            }
        }
    }

    private AgentResponse decideAction(AgentPing ping) {
        if (ping.fd_count > 10 && ping.challenge != null) {
            try {
                String token = generateAuthToken(ping.pid, ping.challenge);
                System.out.println("Generated auth token for PID " + ping.pid + " with challenge: " + ping.challenge);
                return new AgentResponse("kill", ping.pid, token, ping.challenge);
            } catch (Exception e) {
                System.err.println("Error generating auth token: " + e.getMessage());
                return new AgentResponse("ok", 0, null, null);
            }
        } else {
            System.out.println("No action required - FD count: " + ping.fd_count +
                               ", Challenge present: " + (ping.challenge != null));
            return new AgentResponse("ok", 0, null, null);
        }
    }

    private String generateChallenge() {
        byte[] randomBytes = new byte[16];
        random.nextBytes(randomBytes);
        return Base64.getEncoder().encodeToString(randomBytes);
    }

    private String generateAuthToken(int pid, String challenge) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String data = SHARED_SECRET + ":" + pid + ":" + challenge;
        byte[] hash = digest.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AgentPing {
        public String node_id;
        public int pid;
        public int uid;
        public String username;
        public int fd_count;
        public String action;
        public String cmdline;
        public double write_read_ratio;
        public int extension_changes;
        public long timestamp;
        public double threat_score;
        public String challenge;
    }

    public static class AgentResponse {
        public String action;
        public int pid;
        public String auth_token;
        public String challenge;

        public AgentResponse(String action, int pid, String auth_token, String challenge) {
            this.action = action;
            this.pid = pid;
            this.auth_token = auth_token;
            this.challenge = challenge;
        }
    }

    public static void main(String[] args) {
        int port = 8081;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        }
        new Thread(new AgentListener(port)).start();
        try { Thread.currentThread().join(); } catch (InterruptedException ignored) {}
    }
}