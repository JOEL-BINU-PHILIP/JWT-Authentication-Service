package com.company.identity.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Data
@Document(collection = "refresh_tokens")
public class RefreshToken {

    @Id
    private String id;

    private String token;   // actual refresh token string
    private String userId;  // reference to User._id

    private Instant expiresAt;
    private Instant createdAt = Instant.now();
    private boolean revoked = false;
}
