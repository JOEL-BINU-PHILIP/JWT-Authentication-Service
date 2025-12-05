package com.company.identity.controller.admin;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * This controller contains endpoints that ONLY ADMIN users can access.
 *
 * Access control is configured inside SecurityConfig:
 *    .requestMatchers("/admin/**").hasRole("ADMIN")
 *
 * That means:
 *  - Only users with ROLE_ADMIN can call these endpoints.
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    /**
     * A simple protected admin endpoint.
     * If you can see this response, your JWT token has ROLE_ADMIN.
     */
    @GetMapping("/dashboard")
    public String adminDashboard() {
        return "Admin Dashboard (Admin role required)";
    }
}
