package com.company.identity.controller;

import com.company.identity.security.JwtProvider;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Map;

@RestController
public class PublicKeyController {

    private final JwtProvider jwtProvider;

    public PublicKeyController(JwtProvider provider) {
        this.jwtProvider = provider;
    }

    @GetMapping("/auth/public-key")
    public Map<String, String> getPublicKey() {

        String encoded = Base64.getEncoder()
                .encodeToString(jwtProvider.getPublicKey().getEncoded());

        return Map.of("publicKey", encoded);
    }
}
