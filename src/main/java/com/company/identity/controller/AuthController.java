package com.company.identity.controller;

import com.company.identity.dto.AuthResponse;
import com.company.identity.dto.LoginRequest;
import com.company.identity.dto.RegisterRequest;
import com.company.identity.model.RefreshToken;
import com.company.identity.model.Role;
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

    /**
     * REGISTER new user.
     *
     * The request contains username, email, password, and role.
     * This method delegates the work to UserService.
     */
    @PostMapping("/register")
    public User register(@Valid @RequestBody RegisterRequest request) {
        return userService.registerUser(
                request.username(),
                request.email(),
                request.password(),
                request.role()
        );
    }

    /**
     * LOGIN endpoint.
     *
     * Steps:
     * 1. Authenticate username/password using AuthenticationManager
     * 2. If valid, load user info from DB
     * 3. Generate access token + refresh token
     */
    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) throws Exception {

        // This checks username + password
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        // Store authentication in security context for this request
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Fetch user details from DB
        User user = userService.findByUsername(request.username())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Generate tokens
        String jwt = jwtProvider.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createToken(user);

        // Return both tokens + role list
        return new AuthResponse(
                jwt,
                refreshToken.getToken(),
                15 * 60, // expiry in seconds
                user.getRoles().stream().map(Role::getName).toList()
        );
    }

    /**
     * REFRESH ACCESS TOKEN.
     *
     * Client sends refresh token, we:
     * 1. validate it
     * 2. fetch user
     * 3. generate a new access token (JWT)
     */
    @PostMapping("/refresh")
    public AuthResponse refreshToken(@RequestParam String refreshToken) throws Exception {

        // Validate refresh token
        RefreshToken token = refreshTokenService.verifyToken(refreshToken);

        // Find the associated user
        User user = userService.findById(token.getUserId())
                .orElseThrow(() -> new RuntimeException("User no longer exists"));

        // Create a new access token (JWT)
        String newAccessToken = jwtProvider.generateAccessToken(user);

        return new AuthResponse(
                newAccessToken,
                refreshToken, // reuse old refresh token
                15 * 60,
                user.getRoles().stream().map(Role::getName).toList()
        );
    }

    /**
     * LOGOUT endpoint.
     *
     * Simply marks the refresh token as revoked so it cannot be used again.
     */
    @PostMapping("/logout")
    public String logout(@RequestParam String refreshToken) {
        refreshTokenService.revokeToken(refreshToken);
        return "Logged out successfully";
    }
}
