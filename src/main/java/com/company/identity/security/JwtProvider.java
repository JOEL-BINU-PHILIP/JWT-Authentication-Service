package com.company.identity.security;

import com.company.identity.config.JwtConfig;
import com.company.identity.model.Role;
import com.company.identity.model.User;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtProvider {

    private final JwtConfig config;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public JwtProvider(JwtConfig config) {
        this.config = config;
    }

    @PostConstruct
    public void loadKeys() throws Exception {

        // Load private key PEM
        try (InputStream in = getClass().getResourceAsStream(
                config.privateKeyLocation.replace("classpath:", "/"))) {

            if (in == null) {
                throw new RuntimeException("Private key file not found in classpath: " + config.privateKeyLocation);
            }

            String pem = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            this.privateKey = loadPrivateKey(pem);
        }

        // Load public key PEM
        try (InputStream in = getClass().getResourceAsStream(
                config.publicKeyLocation.replace("classpath:", "/"))) {

            if (in == null) {
                throw new RuntimeException("Public key file not found in classpath: " + config.publicKeyLocation);
            }

            String pem = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            this.publicKey = loadPublicKey(pem);
        }
    }

    private RSAPrivateKey loadPrivateKey(String pem) throws Exception {
        String cleaned = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(cleaned);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private RSAPublicKey loadPublicKey(String pem) throws Exception {
        String cleaned = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(cleaned);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public String generateAccessToken(User user) throws JOSEException {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(config.accessTokenValidityMinutes * 60);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(config.issuer)
                .subject(user.getId()) // user MongoDB ID
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiry))
                .claim("roles", user.getRoles()
                        .stream()
                        .map(Role::getName)
                        .collect(Collectors.toList()))
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID("jwt-key-1")
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);

        JWSSigner signer = new RSASSASigner(privateKey);
        jwt.sign(signer);

        return jwt.serialize();
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }
}
