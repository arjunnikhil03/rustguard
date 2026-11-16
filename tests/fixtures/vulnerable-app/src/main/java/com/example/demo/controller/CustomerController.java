package com.example.demo.controller;

import com.example.demo.service.CustomerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/customers")
public class CustomerController {

    @Autowired
    private CustomerService customerService;

    // This is the ONLY place in the whole call chain where the value is
    // ever marked as untrusted. Phase 2 (intra-procedural, single file)
    // would see this method calls customerService.search(name) and stop —
    // no sink visible here at all. Phase 3 has to follow the call into
    // CustomerService, then again into CustomerRepository, to find the
    // actual SQL execution two files away.
    @GetMapping
    public String search(@RequestParam String name) {
        return customerService.searchCustomers(name);
    }
}
