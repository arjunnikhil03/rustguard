package com.example.demo.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import java.security.MessageDigest;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final JdbcTemplate jdbcTemplate;
    private String apiKey = "sk_live_hardcoded_1234567890";

    public UserController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/{id}")
    public String getUser(@PathVariable String id) throws Exception {
        // Vulnerable: string-concatenated SQL built from a path variable
        String result = jdbcTemplate.query("SELECT * FROM users WHERE id = " + id, rs -> {
            return rs.getString("name");
        });

        MessageDigest md = MessageDigest.getInstance("MD5");
        return result;
    }

    @GetMapping("/search")
    public String search(@RequestParam String name) {
        return jdbcTemplate.query("SELECT * FROM users WHERE name = '" + name + "'", rs -> {
            return rs.getString("name");
        });
    }
}
