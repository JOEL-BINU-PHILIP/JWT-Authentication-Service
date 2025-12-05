package com.company.identity.dto;

import java.util.List;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        long expiresInSeconds,
        List<String> roles
) {}
