package com.company.identity.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * This filter runs ONCE per request and checks:
 *  - Whether an incoming request contains a JWT in the Authorization header
 *  - If yes, validate the token
 *  - If valid, authenticate the user inside Spring Security Context
 *
 * This is what enables role-based access without hitting the database every time.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final CustomUserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtProvider jwtProvider, CustomUserDetailsService userDetailsService) {
        this.jwtProvider = jwtProvider;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Read the Authorization header from the incoming request
        String header = request.getHeader("Authorization");

        // Validate that the header exists and contains "Bearer <token>"
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7); // Extract JWT token (remove "Bearer ")

            try {
                // Validate the JWT (signature + expiry)
                if (jwtProvider.validateToken(token)) {

                    // Extract username from the token claims
                    String username = jwtProvider.getUsernameFromToken(token);

                    // ---------------- OPTION A: Load roles from database (recommended) ----------------
                    /**
                     * This approach loads full user details from DB.
                     * Benefit:
                     *  - Always uses the latest user roles if they changed.
                     */
                    var userDetails = userDetailsService.loadUserByUsername(username);

                    // ---------------- OPTION B: Extract roles directly from JWT ----------------
                    /**
                     * This approach avoids DB calls per request.
                     * Benefit:
                     *  - Faster performance.
                     * Risk:
                     *  - If user roles change, old JWT still contains old roles.
                     */
//                    List<SimpleGrantedAuthority> authorities = jwtProvider.getRolesFromToken(token)
//                            .stream()
//                            .map(SimpleGrantedAuthority::new)
//                            .collect(Collectors.toList());
//
//                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
//                            username,
//                            null,
//                            authorities
//                    );

                    // Using Option A’s user details to authenticate
                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    // Mark the user as authenticated for the current request
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }

            } catch (Exception ex) {
                // If token is invalid, clear any existing authentication
                SecurityContextHolder.clearContext();
            }
        }

        // Continue to the next filter or endpoint handler
        filterChain.doFilter(request, response);
    }
}
