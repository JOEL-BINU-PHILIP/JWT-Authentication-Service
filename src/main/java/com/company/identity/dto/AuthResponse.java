package com.company.identity.dto;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        long expiresInSeconds
) {}
