package com.example.demo.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import java.nio.file.Files;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/lookup")
public class LookupController {

    private final JdbcTemplate jdbcTemplate;

    public LookupController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    // Cross-statement SQL injection: the tainted concatenation happens on
    // one line, the sink call happens two lines later. A single-line regex
    // cannot see this; the taint engine tracks it through the `sql` variable.
    @GetMapping("/byName")
    public String byName(@RequestParam String name) {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        System.out.println("Running lookup");
        return jdbcTemplate.query(sql, rs -> rs.getString("name"));
    }

    // Command injection via Runtime.exec, tainted input built on a prior line.
    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws Exception {
        String cmd = "ping -c 1 " + host;
        Runtime.getRuntime().exec(cmd);
        return "ok";
    }

    // Command injection via ProcessBuilder constructor.
    @GetMapping("/run")
    public void run(@RequestParam String arg) throws Exception {
        new ProcessBuilder("sh", "-c", arg).start();
    }

    // SpEL injection.
    @GetMapping("/eval")
    public Object eval(@RequestParam String expr) {
        ExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression(expr).getValue();
    }

    // Path traversal via Files.write.
    @PostMapping("/save")
    public void save(@RequestParam String filename, @RequestBody byte[] data) throws Exception {
        String path = "/uploads/" + filename;
        Files.write(Paths.get(path), data);
    }
}
