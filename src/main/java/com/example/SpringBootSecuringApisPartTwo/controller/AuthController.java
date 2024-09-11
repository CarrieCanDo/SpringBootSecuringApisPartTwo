package com.example.SpringBootSecuringApis.controller;

import com.example.SpringBootSecuringApis.security.JwtTokenUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final JwtTokenUtil jwtTokenUtil;
    private final AuthenticationManager authenticationManager;

    // Constructor Injection
    public AuthController(JwtTokenUtil jwtTokenUtil, AuthenticationManager authenticationManager) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            return jwtTokenUtil.generateToken(username);
        } catch (AuthenticationException e) {
            throw new RuntimeException("Invalid credentials");
        }
    }

    // Admin-specific endpoint, only accessible by users with the 'ADMIN' role
    @GetMapping("/admin/task")
    @PreAuthorize("hasRole('ADMIN')")  // Only ADMIN role can access this method
    public String adminTask() {
        return "This is an admin-only task.";
    }

    // User-specific endpoint, only accessible by users with the 'USER' role
    @GetMapping("/user/task")
    @PreAuthorize("hasRole('USER')")  // Only USER role can access this method
    public String userTask() {
        return "This is a user task.";
    }
}
