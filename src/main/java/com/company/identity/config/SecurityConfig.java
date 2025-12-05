package com.company.identity.config;

import com.company.identity.security.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.company.identity.security.JwtAuthenticationFilter;
import com.company.identity.security.JwtProvider;

/**
 * This class configures the entire Spring Security layer.
 *
 * It decides:
 *  - Which endpoints require authentication
 *  - Which roles can access which URLs
 *  - What authentication mechanism we use (JWT)
 *  - What filters run before requests are processed
 */
@Configuration
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    public SecurityConfig(CustomUserDetailsService uds,
                          PasswordEncoder passwordEncoder,
                          JwtProvider jwtProvider) {

        this.userDetailsService = uds;
        this.passwordEncoder = passwordEncoder;
        this.jwtProvider = jwtProvider;
    }

    /**
     * This configures how username/password authentication works.
     *
     * Internally, Spring will use:
     *  - our UserDetailsService to fetch users from DB
     *  - our PasswordEncoder to check hashed passwords
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

        provider.setUserDetailsService(userDetailsService); // load user from DB
        provider.setPasswordEncoder(passwordEncoder);       // compare hashed passwords

        return provider;
    }

    /**
     * AuthenticationManager is the main object used during login.
     * Spring automatically wires all authentication providers into it.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * This configures HTTP security:
     *  - disable CSRF (not needed for APIs)
     *  - allow public access to /auth/** endpoints
     *  - require specific roles for admin/buyer/seller routes
     *  - add our JWT filter to validate tokens on every request
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // Our custom filter that validates JWT tokens before each request
        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(jwtProvider, userDetailsService);

        http
                .csrf(csrf -> csrf.disable())   // APIs don't use CSRF tokens
                .cors(Customizer.withDefaults()) // allow cross-origin requests
                .authorizeHttpRequests(auth -> auth
                        // These endpoints DO NOT require authentication
                        .requestMatchers(
                                "/auth/register",
                                "/auth/login",
                                "/auth/refresh",
                                "/auth/logout",
                                "/auth/public-key",
                                "/swagger-ui/**",
                                "/v3/api-docs/**"
                        ).permitAll()

                        // Role-based access control
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/seller/**").hasRole("SELLER")
                        .requestMatchers("/buyer/**").hasRole("BUYER")

                        // Any other endpoint MUST be authenticated
                        .anyRequest().authenticated()
                )
                .authenticationProvider(authenticationProvider())

                // Add our JWT filter BEFORE the username/password filter runs
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}


