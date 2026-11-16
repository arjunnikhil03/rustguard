package com.example.demo.controller;

import com.example.demo.service.GreetingService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final JdbcTemplate jdbcTemplate;
    private final GreetingService greetingService;

    public AccountController(JdbcTemplate jdbcTemplate, GreetingService greetingService) {
        this.jdbcTemplate = jdbcTemplate;
        this.greetingService = greetingService;
    }

    @GetMapping("/{id}")
    public String getAccount(@PathVariable String id) {
        // Safe: parameterized query, no concatenation.
        return jdbcTemplate.query(
            "SELECT * FROM accounts WHERE id = ?",
            new Object[]{id},
            (rs, rowNum) -> rs.getString("name")
        ).toString();
    }

    @GetMapping("/greet")
    public String greet(@RequestParam String name) {
        // Crosses into GreetingService, but that method never reaches a
        // sink — should NOT be flagged by Phase 3 cross-file resolution.
        return greetingService.buildGreeting(name);
    }
}
