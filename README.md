# MITM_proxy_over_dfs

A modular, secure proxy system for distributed file storage platforms (e.g., GlusterFS, HDFS) that ensures data resilience against ransomware through transparent encryption and real-time threat detection.

The architecture employs dynamic encryption (AES-GCM / ChaCha20-Poly1305) based on file characteristics, with secure key management handled by HashiCorp Vault under a Zero Knowledge model. It integrates a lightweight Observer-Agent detection mechanism that monitors file operations at the OS level and authorizes secure process termination via challenge-response.

Design patterns used:
- Factory Pattern: for abstracting storage backends and enabling platform agnosticity
- Singleton Pattern: to ensure a single, scalable proxy instance across services
- Strategy Pattern: for selecting the optimal encryption algorithm at runtime
- Observer Pattern: for real-time communication between monitoring agents and the central controller

Key features:
- Transparent encryption in transit and at rest
- Dynamic algorithm selection for performance optimization
- Real-time ransomware detection with secure kill protocol
- Scalable, platform-agnostic design deployed via Docker and OpenStack

Technologies: Java, C, Spring Boot, Docker, HashiCorp Vault, GlusterFS, HDFS

