package com.company.identity.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {

    @Value("${jwt.issuer}")
    public String issuer;

    @Value("${jwt.access-token-validity-minutes}")
    public long accessTokenValidityMinutes;

    @Value("${jwt.refresh-token-validity-days}")
    public long refreshTokenValidityDays;

    @Value("${jwt.key-pair.private-key-location}")
    public String privateKeyLocation;

    @Value("${jwt.key-pair.public-key-location}")
    public String publicKeyLocation;
}
