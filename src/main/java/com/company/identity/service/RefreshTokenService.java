package com.company.identity.service;

import com.company.identity.model.RefreshToken;
import com.company.identity.model.User;
import com.company.identity.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    private final long validitySeconds;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            @Value("${jwt.refresh-token-validity-days}") long validityDays
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.validitySeconds = validityDays * 24 * 3600;
    }

    public RefreshToken createToken(User user) {
        RefreshToken token = new RefreshToken();

        token.setToken(generateSecureString());
        token.setUserId(user.getId());
        token.setExpiresAt(Instant.now().plusSeconds(validitySeconds));
        token.setRevoked(false);

        refreshTokenRepository.save(token);
        return token;
    }

    public RefreshToken verifyToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .filter(t -> !t.isRevoked())
                .filter(t -> t.getExpiresAt().isAfter(Instant.now()))
                .orElseThrow(() -> new RuntimeException("Invalid or expired refresh token"));
    }

    public void revokeToken(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(t -> {
            t.setRevoked(true);
            refreshTokenRepository.save(t);
        });
    }

    private String generateSecureString() {
        byte[] bytes = new byte[64];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
