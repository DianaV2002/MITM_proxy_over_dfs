package org.example;

import org.example.observer.AgentListener;

public class ObserverMain {
    public static void main(String[] args) {
        int port = 8081; // Or read from args/env if desired
        new Thread(new AgentListener(port)).start();
        System.out.println("AgentListener started on port " + port);
        // Keep the main thread alive
        try { Thread.currentThread().join(); } catch (InterruptedException ignored) {}
    }
} 