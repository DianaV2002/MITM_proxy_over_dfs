#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <jansson.h>
#include <pwd.h>
#include <syslog.h>
#include <openssl/sha.h>



#define MAX_PROCESSES 1024
#define SCAN_INTERVAL 1
#define FD_THRESHOLD 10
#define OBSERVER_IP "172.30.6.61"
#define OBSERVER_PORT 8081
#define NODE_ID "gluster-node"
#define MAX_PATH 512
#define LOG_FILE "/var/log/gluster_ransomware_agent.log"
#define EXTENSION_CHANGES_THRESHOLD 5
#define SUSPICIOUS_EXTENSIONS_COUNT 20
#define SHARED_SECRET "gluster_security_key_2024"

// Allowed users who can legitimately access GlusterFS files
const char *ALLOWED_USERS[] = {"gluster", "root"};
const int ALLOWED_USER_COUNT = sizeof(ALLOWED_USERS)/sizeof(ALLOWED_USERS[0]);

// Known ransomware file extensions
const char *SUSPICIOUS_EXTENSIONS[] = {
    ".locked", ".encrypted", ".crypto", ".crypt", ".crypted",
    ".crypz", ".cry", ".encode", ".enc", ".ezz",
    ".exx", ".vault", ".zzz", ".wncry", ".wcry",
    ".WNCRY", ".lokd", ".locky", ".zepto", ".cerber"
};

typedef struct {
    int pid;
    uid_t uid;
    char username[32];
    char cmdline[256];
    int fd_count;
    int fd_last_count;
    time_t last_updated;
    int suspicious_count;
    int extension_changes;
    double write_read_ratio;
    int total_reads;
    int total_writes;
    char accessed_files[5][MAX_PATH];  // Track last 5 accessed files
    int file_index;
    char challenge[32];
} process_info_t;

process_info_t processes[MAX_PROCESSES];
int process_count = 0;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int mutex_initialized = 0;
FILE *log_file = NULL;

// Add response structure
typedef struct {
    char action[32];
    int pid;
    char auth_token[256];
    char challenge[256];
} observer_response_t;

// Add new mutex for challenge verification
static pthread_mutex_t challenge_mutex = PTHREAD_MUTEX_INITIALIZER;

// Forward declarations
void log_message(const char *level, const char *format, ...);
int detect_extension_change(const char *filepath);
int check_file_content(const char *filepath);
int check_suspicious_extension(const char *filepath);
char* base64_encode(const unsigned char* data, size_t input_length);
unsigned char* base64_decode(const char* input, size_t* output_length);
void generate_challenge(char *out, size_t out_size);
int verify_and_kill(int pid, const char *auth_token, const char *challenge);
void store_challenge_for_pid(int pid, const char *challenge);

// Get the user ID for a process
int get_process_uid(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    
    char line[256];
    uid_t uid = -1;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            sscanf(line, "Uid:\t%d", &uid);
            break;
        }
    }
    fclose(fp);
    return uid;
}

void store_challenge_for_pid(int pid, const char *challenge) {
    log_message("DEBUG", ">> store_challenge_for_pid: Starting for pid %d", pid);
    log_message("DEBUG", ">> store_challenge_for_pid: Current process_count=%d", process_count);
    
    if (pid <= 0) {
        log_message("ERROR", ">> store_challenge_for_pid: Invalid PID %d", pid);
        return;
    }
    
    if (!challenge || strlen(challenge) == 0) {
        log_message("ERROR", ">> store_challenge_for_pid: Invalid challenge for PID %d", pid);
        return;
    }
    
    pthread_mutex_lock(&mutex);
    log_message("DEBUG", ">> store_challenge_for_pid: Mutex locked");
    
    // Initialize the process array if needed
    if (process_count == 0) {
        log_message("DEBUG", ">> store_challenge_for_pid: Initializing first process entry");
        memset(&processes[0], 0, sizeof(process_info_t));
        processes[0].pid = pid;
        strncpy(processes[0].challenge, challenge, sizeof(processes[0].challenge) - 1);
        processes[0].challenge[sizeof(processes[0].challenge) - 1] = '\0';
        process_count = 1;
        log_message("DEBUG", ">> store_challenge_for_pid: First process entry initialized");
        pthread_mutex_unlock(&mutex);
        log_message("DEBUG", ">> store_challenge_for_pid: Mutex unlocked after initialization");
        return;
    }
    
    int found = 0;
    for (int i = 0; i < process_count; i++) {
        log_message("DEBUG", ">> store_challenge_for_pid: Checking process[%d], pid=%d", i, processes[i].pid);
        if (processes[i].pid == pid) {
            log_message("DEBUG", ">> store_challenge_for_pid: Found process at index %d", i);
            strncpy(processes[i].challenge, challenge, sizeof(processes[i].challenge) - 1);
            processes[i].challenge[sizeof(processes[i].challenge) - 1] = '\0';
            found = 1;
            log_message("DEBUG", ">> store_challenge_for_pid: Stored challenge: %s", challenge);
            break;
        }
    }
    
    if (!found) {
        log_message("DEBUG", ">> store_challenge_for_pid: Process not found, adding new entry");
        if (process_count < MAX_PROCESSES) {
            memset(&processes[process_count], 0, sizeof(process_info_t));
            processes[process_count].pid = pid;
            strncpy(processes[process_count].challenge, challenge, sizeof(processes[process_count].challenge) - 1);
            processes[process_count].challenge[sizeof(processes[process_count].challenge) - 1] = '\0';
            process_count++;
            log_message("DEBUG", ">> store_challenge_for_pid: Added new process entry, new count=%d", process_count);
        } else {
            log_message("ERROR", ">> store_challenge_for_pid: Process array full, cannot store challenge");
        }
    }
    
    pthread_mutex_unlock(&mutex);
    log_message("DEBUG", ">> store_challenge_for_pid: Mutex unlocked");
}


// Get process command line
void get_process_cmdline(int pid, char *cmdline, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *fp = fopen(path, "r");
    
    if (!fp) {
        cmdline[0] = '\0';
        return;
    }
    
    size_t bytes_read = fread(cmdline, 1, size - 1, fp);
    fclose(fp);
    
    if (bytes_read > 0) {
        // Replace null bytes with spaces for better readability
        for (size_t i = 0; i < bytes_read - 1; i++) {
            if (cmdline[i] == '\0') cmdline[i] = ' ';
        }
        cmdline[bytes_read] = '\0';
    } else {
        cmdline[0] = '\0';
    }
}

// Get username from UID
void get_username(uid_t uid, char *username, size_t size) {
    struct passwd *pw = getpwuid(uid);
    if (pw) {
        strncpy(username, pw->pw_name, size - 1);
        username[size - 1] = '\0';
    } else {
        snprintf(username, size, "%d", uid);
    }
}

// Check if a user ID is in the allowed list
int is_allowed_uid(uid_t uid) {
    for (int i = 0; i < ALLOWED_USER_COUNT; i++) {
        struct passwd *pw = getpwnam(ALLOWED_USERS[i]);
        if (pw && pw->pw_uid == uid) return 1;
    }
    return 0;
}

// Count file descriptors on a specific path
int count_fd_on_path(int pid, const char *path_filter, process_info_t *proc_info) {
    char fd_dir_path[64];
    snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%d/fd", pid);
    DIR *dir = opendir(fd_dir_path);
    if (!dir) return 0;

    int count = 0;
    int reads = 0, writes = 0;
    struct dirent *entry;
    char link_path[512], target_path[512];
    
    while ((entry = readdir(dir))) {
        if (!isdigit(entry->d_name[0])) continue;
        
        snprintf(link_path, sizeof(link_path), "%s/%s", fd_dir_path, entry->d_name);
        ssize_t len = readlink(link_path, target_path, sizeof(target_path) - 1);
        
        if (len != -1) {
            target_path[len] = '\0';
            
            if (strstr(target_path, path_filter)) {
                count++;
                
                // Check file access mode
                int fd_num = atoi(entry->d_name);
                char fd_info_path[512];
                snprintf(fd_info_path, sizeof(fd_info_path), "/proc/%d/fdinfo/%s", pid, entry->d_name);
                FILE *fd_info = fopen(fd_info_path, "r");
                
                if (fd_info) {
                    char info_line[256];
                    int flags = 0;
                    
                    while (fgets(info_line, sizeof(info_line), fd_info)) {
                        if (strncmp(info_line, "flags:", 6) == 0) {
                            sscanf(info_line, "flags:\t%o", &flags);
                            break;
                        }
                    }
                    fclose(fd_info);
                    
                    // Check access modes (O_RDONLY = 0, O_WRONLY = 1, O_RDWR = 2)
                    int access_mode = flags & O_ACCMODE;
                    if (access_mode == O_WRONLY || access_mode == O_RDWR) {
                        writes++;
                        
                        // Store accessed file in history
                        if (proc_info) {
                            strncpy(proc_info->accessed_files[proc_info->file_index], target_path, MAX_PATH - 1);
                            proc_info->accessed_files[proc_info->file_index][MAX_PATH - 1] = '\0';
                            proc_info->file_index = (proc_info->file_index + 1) % 5;
                            
                            // Check for suspicious extension
                            if (check_suspicious_extension(target_path)) {
                                proc_info->extension_changes++;
                            }
                            
                            // Check if this might be a file content change
                            if (detect_extension_change(target_path)) {
                                proc_info->extension_changes++;
                            }
                        }
                    }
                    if (access_mode == O_RDONLY || access_mode == O_RDWR) {
                        reads++;
                    }
                }
            }
        }
    }
    
    closedir(dir);
    
    if (proc_info) {
        proc_info->total_reads += reads;
        proc_info->total_writes += writes;
        
        // Calculate write/read ratio
        if (proc_info->total_reads > 0) {
            proc_info->write_read_ratio = (double)proc_info->total_writes / proc_info->total_reads;
        } else if (proc_info->total_writes > 0) {
            proc_info->write_read_ratio = 999.0; // High value for writes without reads
        }
    }
    
    return count;
}

// Check if a file has a suspicious extension
int check_suspicious_extension(const char *filepath) {
    for (int i = 0; i < SUSPICIOUS_EXTENSIONS_COUNT; i++) {
        if (strstr(filepath, SUSPICIOUS_EXTENSIONS[i])) {
            return 1;
        }
    }
    return 0;
}

// Detect if a file might have had its extension changed (common in ransomware)
int detect_extension_change(const char *filepath) {
    // Check if the file has double extension like "document.docx.encrypted"
    const char *last_dot = strrchr(filepath, '.');
    if (!last_dot) return 0;
    
    // Find the second-to-last dot
    char *file_copy = strdup(filepath);
    file_copy[last_dot - filepath] = '\0';
    const char *second_last_dot = strrchr(file_copy, '.');
    
    int result = 0;
    if (second_last_dot) {
        // Check if the part between the last two dots is a common document type
        const char *common_types[] = {"doc", "xls", "ppt", "pdf", "jpg", "png", "txt", "csv"};
        const int type_count = sizeof(common_types) / sizeof(common_types[0]);
        
        char ext_buffer[10] = {0};
        int len = last_dot - (second_last_dot + 1);
        if (len < 10) {
            strncpy(ext_buffer, second_last_dot + 1, len);
            ext_buffer[len] = '\0';
            
            for (int i = 0; i < type_count; i++) {
                if (strcasecmp(ext_buffer, common_types[i]) == 0) {
                    result = 1;
                    break;
                }
            }
        }
    }
    
    free(file_copy);
    return result;
}
void generate_challenge(char *out, size_t out_size) {
    const char *fallback = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t len = strlen(fallback);

    if (out_size < 2) {
        if (out_size > 0) out[0] = '\0';
        return;
    }

    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)(time(NULL) ^ getpid()));
        seeded = 1;
    }

    for (size_t i = 0; i < out_size - 1; i++) {
        out[i] = fallback[rand() % len];
    }

    out[out_size - 1] = '\0';
}



int verify_and_kill(int pid, const char *auth_token, const char *challenge) {
    if (!challenge || strlen(challenge) == 0) {
        log_message("ERROR", "Invalid challenge provided for process %d", pid);
        return 0;
    }

    // Proceed with verification using provided challenge
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char data[512];
    snprintf(data, sizeof(data), "%s:%d:%s", SHARED_SECRET, pid, challenge);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, strlen(data));
    SHA256_Final(hash, &sha256);

    char expected_token[256];
    char *b64 = base64_encode(hash, SHA256_DIGEST_LENGTH);
    strncpy(expected_token, b64, sizeof(expected_token) - 1);
    expected_token[sizeof(expected_token) - 1] = '\0';
    free(b64);

    // Decode both tokens for comparison
    size_t expected_len, received_len;
    unsigned char *expected_decoded = base64_decode(expected_token, &expected_len);
    unsigned char *received_decoded = base64_decode(auth_token, &received_len);
    
    int result = 0;
    if (expected_decoded && received_decoded && 
        expected_len == received_len && 
        memcmp(expected_decoded, received_decoded, expected_len) == 0) {
        log_message("INFO", "Authorization verified, killing process %d", pid);
        if (kill(pid, SIGKILL) == 0) {
            log_message("INFO", "Successfully killed process %d", pid);
            result = 1;
        } else {
            log_message("ERROR", "Failed to kill process %d: %s", pid, strerror(errno));
        }
    } else {
        log_message("ERROR", "Invalid authorization token for process %d", pid);
        log_message("DEBUG", "Expected token: %s", expected_token);
        log_message("DEBUG", "Received token: %s", auth_token);
        log_message("DEBUG", "Challenge used: %s", challenge);
    }

    free(expected_decoded);
    free(received_decoded);
    return result;
}




// Base64 encoding function
char* base64_encode(const unsigned char* data, size_t input_length) {
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(output_length + 1);
    if (encoded_data == NULL) return NULL;
    
    size_t i, j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;
        
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        
        encoded_data[j++] = base64_chars[(triple >> 18) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 12) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 6) & 0x3F];
        encoded_data[j++] = base64_chars[triple & 0x3F];
    }
    
    // Add padding
    for (i = 0; i < (3 - input_length % 3) % 3; i++) {
        encoded_data[output_length - 1 - i] = '=';
    }
    
    encoded_data[output_length] = '\0';
    return encoded_data;
}

// Base64 decoding function
unsigned char* base64_decode(const char* input, size_t* output_length) {
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t input_length = strlen(input);
    size_t padding = 0;
    
    // Count padding
    if (input_length > 0) {
        if (input[input_length - 1] == '=') padding++;
        if (input[input_length - 2] == '=') padding++;
    }
    
    *output_length = (input_length / 4) * 3 - padding;
    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;
    
    size_t i, j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = input[i] == '=' ? 0 : strchr(base64_chars, input[i]) - base64_chars;
        uint32_t sextet_b = input[i + 1] == '=' ? 0 : strchr(base64_chars, input[i + 1]) - base64_chars;
        uint32_t sextet_c = input[i + 2] == '=' ? 0 : strchr(base64_chars, input[i + 2]) - base64_chars;
        uint32_t sextet_d = input[i + 3] == '=' ? 0 : strchr(base64_chars, input[i + 3]) - base64_chars;
        
        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;
        
        if (j < *output_length) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = triple & 0xFF;
        
        i += 4;
    }
    
    return decoded_data;
}

static int ensure_mutex_initialized() {
    if (!mutex_initialized) {
        int ret = pthread_mutex_init(&mutex, NULL);
        if (ret != 0) {
            log_message("ERROR", "Failed to initialize mutex: %s", strerror(ret));
            return 0;
        }
        mutex_initialized = 1;
        log_message("DEBUG", "Mutex initialized successfully");
    }
    return 1;
}

void send_alert(int pid, uid_t uid, const char *username, const char *cmdline, int fd_count, 
                double write_ratio, int extension_changes) {
    log_message("DEBUG", ">> send_alert: PID=%d, UID=%d", pid, uid);

    log_message("DEBUG", ">> Step 1: Creating socket");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_message("ERROR", "Socket creation failed: %s", strerror(errno));
        return;
    }
    log_message("DEBUG", ">> Step 2: Socket created");

    log_message("DEBUG", ">> Step 3: Setting timeout");
    struct timeval timeout = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    log_message("DEBUG", ">> Step 4: Preparing sockaddr_in");
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(OBSERVER_PORT);
    inet_pton(AF_INET, OBSERVER_IP, &addr.sin_addr);

    log_message("DEBUG", ">> Step 5: Connecting to observer");
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_message("ERROR", "Connect failed: %s", strerror(errno));
        close(sock);
        return;
    }
    log_message("DEBUG", ">> Step 6: Connected to observer");

    log_message("DEBUG", ">> Step 7: Building JSON payload");
    json_t *json = json_object();
    json_object_set_new(json, "node_id", json_string(NODE_ID));
    json_object_set_new(json, "pid", json_integer(pid));
    json_object_set_new(json, "uid", json_integer(uid));
    json_object_set_new(json, "username", json_string(username));
    json_object_set_new(json, "fd_count", json_integer(fd_count));
    json_object_set_new(json, "action", json_string("alert"));
    json_object_set_new(json, "cmdline", json_string(cmdline));
    json_object_set_new(json, "write_read_ratio", json_real(write_ratio));
    json_object_set_new(json, "extension_changes", json_integer(extension_changes));
    json_object_set_new(json, "timestamp", json_integer(time(NULL)));
    log_message("DEBUG", ">> Step 8: Basic JSON fields set");

    log_message("DEBUG", ">> Step 9: Handling challenge");
    char challenge[32] = "";
    
    // Find existing challenge for this PID
    const char *existing_challenge = NULL;
    pthread_mutex_lock(&challenge_mutex);
    for (int i = 0; i < process_count; i++) {
        if (processes[i].pid == pid) {
            existing_challenge = processes[i].challenge;
            break;
        }
    }
    pthread_mutex_unlock(&challenge_mutex);
    
    log_message("DEBUG", ">> Step 9.3: Checking challenge");
    if (!existing_challenge || strlen(existing_challenge) == 0) {
        // Generate new challenge
        const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        size_t charset_size = strlen(charset);
        srand(time(NULL) ^ getpid());
        for (size_t i = 0; i < sizeof(challenge) - 1; ++i) {
            challenge[i] = charset[rand() % charset_size];
        }
        challenge[sizeof(challenge) - 1] = '\0';
        log_message("DEBUG", ">> Step 9.4: Challenge generated: %s", challenge);
        
        // Store the challenge
        pthread_mutex_lock(&challenge_mutex);
        int found = 0;
        for (int i = 0; i < process_count; i++) {
            if (processes[i].pid == pid) {
                strncpy(processes[i].challenge, challenge, sizeof(processes[i].challenge) - 1);
                processes[i].challenge[sizeof(processes[i].challenge) - 1] = '\0';
                existing_challenge = processes[i].challenge;
                found = 1;
                log_message("DEBUG", ">> Step 9.5: Challenge stored in existing process entry");
                break;
            }
        }
        
        if (!found && process_count < MAX_PROCESSES) {
            memset(&processes[process_count], 0, sizeof(process_info_t));
            processes[process_count].pid = pid;
            strncpy(processes[process_count].challenge, challenge, sizeof(processes[process_count].challenge) - 1);
            processes[process_count].challenge[sizeof(processes[process_count].challenge) - 1] = '\0';
            existing_challenge = processes[process_count].challenge;
            process_count++;
            log_message("DEBUG", ">> Step 9.6: Challenge stored in new process entry");
        }
        pthread_mutex_unlock(&challenge_mutex);
    } else {
        // Use existing challenge
        strncpy(challenge, existing_challenge, sizeof(challenge) - 1);
        challenge[sizeof(challenge) - 1] = '\0';
        log_message("DEBUG", ">> Step 9.7: Using existing challenge");
    }
    
    log_message("DEBUG", ">> Step 9.8: Challenge handling completed");

    json_object_set_new(json, "challenge", json_string(challenge));
    log_message("DEBUG", ">> Step 10: Challenge set in JSON");

    char *json_str = json_dumps(json, JSON_COMPACT);
    json_decref(json);
    log_message("DEBUG", ">> Step 11: JSON string built: %s", json_str);

    char final_msg[2048];
    snprintf(final_msg, sizeof(final_msg), "%s\n", json_str);
    free(json_str);

    log_message("DEBUG", ">> Step 12: Sending final message to observer: %s", final_msg);
    ssize_t sent = write(sock, final_msg, strlen(final_msg));
    log_message("DEBUG", ">> Step 13: write() returned: %zd", sent);
    if (sent < 0) {
        log_message("ERROR", "Write failed: %s", strerror(errno));
        close(sock);
        return;
    }

    log_message("DEBUG", ">> Step 14: Waiting for response from observer");
    char buffer[1024] = {0};
    ssize_t recvd = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (recvd > 0) {
        buffer[recvd] = '\0';
        log_message("DEBUG", ">> Step 15: Received response: %s", buffer);
        
        // Process response
        json_error_t error;
        json_t *resp_json = json_loads(buffer, 0, &error);
        if (resp_json) {
            json_t *action_json = json_object_get(resp_json, "action");
            json_t *pid_json = json_object_get(resp_json, "pid");
            json_t *auth_token_json = json_object_get(resp_json, "auth_token");
            json_t *challenge_json = json_object_get(resp_json, "challenge");
            
            if (action_json && pid_json && auth_token_json && challenge_json && 
                json_is_string(action_json) && json_is_integer(pid_json) && 
                json_is_string(auth_token_json) && json_is_string(challenge_json)) {
                
                const char *action = json_string_value(action_json);
                int target_pid = json_integer_value(pid_json);
                const char *auth_token = json_string_value(auth_token_json);
                const char *resp_challenge = json_string_value(challenge_json);
                
                if (strcmp(action, "kill") == 0 && target_pid == pid) {
                    log_message("INFO", "Received kill instruction for PID %d", target_pid);
                    if (verify_and_kill(target_pid, auth_token, resp_challenge)) {
                        log_message("INFO", "Successfully terminated suspicious process %d", target_pid);
                    } else {
                        log_message("ERROR", "Failed to verify and kill process %d", target_pid);
                    }
                }
            }
            json_decref(resp_json);
        } else {
            log_message("ERROR", "Failed to parse JSON response: %s", error.text);
        }
    } else {
        log_message("WARNING", ">> Step 15: No response or recv failed: %s", strerror(errno));
    }

    log_message("DEBUG", ">> Step 16: Closing socket");
    close(sock);
    log_message("DEBUG", ">> send_alert: Completed for PID=%d", pid);
}

// Log messages to syslog and file
void log_message(const char *level, const char *format, ...) {
    va_list args;
    char message[1024];
    
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    // Log to file
    if (log_file) {
        time_t now = time(NULL);
        struct tm *tm_now = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_now);
        
        fprintf(log_file, "[%s] [%s] %s\n", timestamp, level, message);
        fflush(log_file);
    }
    
    // Log to syslog
    int priority = LOG_INFO;
    if (strcmp(level, "ERROR") == 0) priority = LOG_ERR;
    else if (strcmp(level, "WARNING") == 0) priority = LOG_WARNING;
    else if (strcmp(level, "DEBUG") == 0) priority = LOG_DEBUG;
    
    syslog(priority, "%s", message);
}

void scan_processes() {
    log_message("DEBUG", ">> scan_processes: Starting process scan");
    DIR *proc = opendir("/proc");
    if (!proc) {
        log_message("ERROR", "Failed to open /proc directory: %s", strerror(errno));
        return;
    }
    log_message("DEBUG", ">> scan_processes: Opened /proc directory");

    pthread_mutex_lock(&mutex);
    log_message("DEBUG", ">> scan_processes: Locked mutex, current process_count=%d", process_count);
    
    int curr_count = 0;
    struct dirent *entry;
    
    while ((entry = readdir(proc)) && curr_count < MAX_PROCESSES) {
        if (!isdigit(entry->d_name[0])) continue;
        
        int pid = atoi(entry->d_name);
        uid_t uid = get_process_uid(pid);
        if (uid == (uid_t)-1) {
            //log_message("DEBUG", ">> scan_processes: Skipping process %d (invalid UID)", pid);
            continue;
        }
        
        int existing_idx = -1;
        for (int i = 0; i < process_count; i++) {
            if (processes[i].pid == pid) {
                existing_idx = i;
                break;
            }
        }
        
        char cmdline[256] = {0};
        char username[32] = {0};
        get_process_cmdline(pid, cmdline, sizeof(cmdline));
        get_username(uid, username, sizeof(username));
        
        process_info_t temp_info = {0};
        if (existing_idx >= 0) {
            temp_info = processes[existing_idx];
            log_message("DEBUG", ">> scan_processes: Found existing process %d at index %d", pid, existing_idx);
        }
        
        int fd_count = count_fd_on_path(pid, "/mnt/glusterfs", &temp_info);
        if (fd_count == 0) {
            //log_message("DEBUG", ">> scan_processes: Skipping process %d (no GlusterFS FDs)", pid);
            continue;
        }
        
        if (existing_idx == -1) {
            // New process
            int idx = curr_count++;
            log_message("DEBUG", ">> scan_processes: Adding new process %d at index %d", pid, idx);
            processes[idx].pid = pid;
            processes[idx].uid = uid;
            processes[idx].fd_count = fd_count;
            processes[idx].fd_last_count = 0;
            processes[idx].last_updated = time(NULL);
            processes[idx].suspicious_count = 0;
            processes[idx].extension_changes = temp_info.extension_changes;
            processes[idx].write_read_ratio = temp_info.write_read_ratio;
            processes[idx].total_reads = temp_info.total_reads;
            processes[idx].total_writes = temp_info.total_writes;
            processes[idx].file_index = 0;
            processes[idx].challenge[0] = '\0';
            
            strncpy(processes[idx].username, username, sizeof(processes[idx].username) - 1);
            strncpy(processes[idx].cmdline, cmdline, sizeof(processes[idx].cmdline) - 1);
            
            log_message("INFO", "New process tracking: PID %d (User: %s) %s", pid, username, cmdline);
            
            if (!is_allowed_uid(uid) && fd_count > FD_THRESHOLD) {
                log_message("WARNING", "High file descriptor count detected: PID %d (User: %s) - FD: %d", 
                           pid, username, fd_count);
                send_alert(pid, uid, username, cmdline, fd_count, 
                          temp_info.write_read_ratio, temp_info.extension_changes);
            }
        } else {
            // Existing process
            int idx = existing_idx;
            log_message("DEBUG", ">> scan_processes: Updating existing process %d at index %d", pid, idx);
            int fd_diff = fd_count - processes[idx].fd_last_count;
            time_t now = time(NULL);
            double interval = (now - processes[idx].last_updated > 0) ? 
                             (double)fd_diff / (now - processes[idx].last_updated) : 0;
            
            processes[idx].fd_last_count = processes[idx].fd_count;
            processes[idx].fd_count = fd_count;
            processes[idx].last_updated = now;
            processes[idx].total_reads = temp_info.total_reads;
            processes[idx].total_writes = temp_info.total_writes;
            processes[idx].write_read_ratio = temp_info.write_read_ratio;
            processes[idx].extension_changes = temp_info.extension_changes;
            strncpy(processes[idx].cmdline, cmdline, sizeof(processes[idx].cmdline) - 1);
            
            if (!is_allowed_uid(uid) && fd_count > FD_THRESHOLD) {
                log_message("WARNING", "High file descriptor count detected: PID %d (User: %s) - FD: %d", 
                           pid, username, fd_count);
                send_alert(pid, uid, username, cmdline, fd_count, 
                          processes[idx].write_read_ratio, processes[idx].extension_changes);
            }
            
            int is_suspicious = 0;
            if (processes[idx].write_read_ratio > 3.0) is_suspicious++;
            if (processes[idx].extension_changes >= EXTENSION_CHANGES_THRESHOLD) is_suspicious++;
            
           if (is_suspicious > 0) {
            processes[idx].suspicious_count++;
            log_message("WARNING", "Additional suspicious indicators...");

            if (!is_allowed_uid(uid)) {
                log_message("WARNING", "Triggering alert for suspicious PID %d (User: %s)", pid, username);
                send_alert(pid, uid, username, cmdline, fd_count,
                        processes[idx].write_read_ratio, processes[idx].extension_changes);
            } else if (processes[idx].suspicious_count > 0) {
                processes[idx].suspicious_count--;
            }
            
            if (idx != curr_count) {
                processes[curr_count] = processes[idx];
            }
            curr_count++;
           }
        }
    }
    
    process_count = curr_count;
    log_message("DEBUG", ">> scan_processes: Updated process_count to %d", process_count);
    pthread_mutex_unlock(&mutex);
    log_message("DEBUG", ">> scan_processes: Unlocked mutex");
    
    closedir(proc);
    log_message("DEBUG", ">> scan_processes: Completed process scan");
}

// Signal handler for graceful shutdown
void handle_signal(int sig) {
    log_message("INFO", "Received signal %d, shutting down...", sig);
    
    if (log_file) {
        fclose(log_file);
    }
    
    closelog();
    exit(0);
}

// Main function
int main() {
    // Initialize logging
    openlog("gluster_ransomware_agent", LOG_PID | LOG_CONS, LOG_DAEMON);
    log_file = fopen(LOG_FILE, "a");
    
    if (!log_file) {
        syslog(LOG_ERR, "Failed to open log file: %s", LOG_FILE);
    }
    
    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    log_message("INFO", "GlusterFS Ransomware Detection Agent started...");
    
    // Main monitoring loop
    while (1) {
        scan_processes();
        sleep(SCAN_INTERVAL);
    }
    
    return 0;
}