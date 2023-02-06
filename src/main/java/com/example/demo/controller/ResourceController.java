package com.example.demo.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class ResourceController {
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    @GetMapping("/user-data")
    String userData(Authentication authentication) {
        log.info("=== GET /user-get === auth.name = {}", authentication.getName());
        log.info("=== GET /user-get === auth = {}", authentication);
        return "user data";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin-data")
    String adminData(Authentication authentication) {
        log.info("=== GET /admin-get === auth.name = {}", authentication.getName());
        log.info("=== GET /admin-get === auth = {}", authentication);
        return "admin data";
    }
}
