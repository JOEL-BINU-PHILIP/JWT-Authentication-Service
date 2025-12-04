package com.company.identity.controller;

import com.company.identity.dto.AuthResponse;
import com.company.identity.dto.LoginRequest;
import com.company.identity.dto.RegisterRequest;
import com.company.identity.model.RefreshToken;
import com.company.identity.model.User;
import com.company.identity.security.JwtProvider;
import com.company.identity.service.RefreshTokenService;
import com.company.identity.service.UserService;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final JwtProvider jwtProvider;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserService userService,
                          RefreshTokenService refreshTokenService,
                          JwtProvider jwtProvider,
                          AuthenticationManager authenticationManager,
                          PasswordEncoder passwordEncoder) {

        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
        this.jwtProvider = jwtProvider;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
    }

    // ---------------- REGISTER ----------------
    @PostMapping("/register")
    public User register(@Valid @RequestBody RegisterRequest request) {

        return userService.registerUser(
                request.username(),
                request.email(),
                request.password(),
                request.role()  // ROLE_BUYER or ROLE_SELLER
        );
    }

    // ---------------- LOGIN ----------------
    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) throws Exception {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = userService.findByUsername(request.username())
                .orElseThrow(() -> new RuntimeException("User not found"));

        String jwt = jwtProvider.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createToken(user);

        return new AuthResponse(
                jwt,
                refreshToken.getToken(),
                15 * 60  // 15 minutes
        );
    }

    // ---------------- REFRESH TOKEN ----------------
    @PostMapping("/refresh")
    public AuthResponse refreshToken(@RequestParam String refreshToken) throws Exception {

        RefreshToken token = refreshTokenService.verifyToken(refreshToken);

        User user = userService.findById(token.getUserId())
                .orElseThrow(() -> new RuntimeException("User no longer exists"));

        String newAccessToken = jwtProvider.generateAccessToken(user);

        return new AuthResponse(
                newAccessToken,
                refreshToken,
                15 * 60
        );
    }

    // ---------------- LOGOUT ----------------
    @PostMapping("/logout")
    public String logout(@RequestParam String refreshToken) {

        refreshTokenService.revokeToken(refreshToken);
        return "Logged out successfully";
    }
}
