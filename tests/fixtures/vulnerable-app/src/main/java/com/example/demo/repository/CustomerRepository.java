package com.example.demo.repository;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class CustomerRepository {

    private final JdbcTemplate jdbcTemplate;

    public CustomerRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    // No annotation here at all — this method has no idea it's ever called
    // with untrusted input. That's the whole point of Phase 3: the taint
    // engine has to follow the call chain to find this out.
    public String findByName(String customerName) {
        String sql = "SELECT * FROM customers WHERE name = '" + customerName + "'";
        return jdbcTemplate.query(sql, rs -> rs.getString("name"));
    }
}
