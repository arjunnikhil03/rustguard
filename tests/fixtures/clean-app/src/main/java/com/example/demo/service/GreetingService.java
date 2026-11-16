package com.example.demo.service;

import org.springframework.stereotype.Service;

@Service
public class GreetingService {

    // Tainted input flows in here from a controller, crosses a file
    // boundary, but never reaches anything resembling a sink. Phase 3's
    // cross-file resolution should follow the call and correctly find
    // nothing to report.
    public String buildGreeting(String name) {
        return "Hello, " + name + "!";
    }
}
