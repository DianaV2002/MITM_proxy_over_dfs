package org.example.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

public class EncryptedContent {
    @JsonProperty("file_id")
    private String fileId;
    
    @JsonProperty("ciphertext")
    private String ciphertext;

    public EncryptedContent() {}

    public EncryptedContent(String fileId, String ciphertext) {
        this.fileId = fileId;
        this.ciphertext = ciphertext;
    }

    public String getFileId() {
        return fileId;
    }

    public void setFileId(String fileId) {
        this.fileId = fileId;
    }

    public String getCiphertext() {
        return ciphertext;
    }

    public void setCiphertext(String ciphertext) {
        this.ciphertext = ciphertext;
    }

    public String toJson() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static EncryptedContent fromJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, EncryptedContent.class);
    }
} 