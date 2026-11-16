package com.example.demo.service;

import com.example.demo.repository.CustomerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CustomerService {

    @Autowired
    private CustomerRepository customerRepository;

    // Also no annotation, also has no idea its argument might be untrusted.
    public String searchCustomers(String query) {
        // No concatenation here at all — this method just passes the value
        // straight through to the repository. Proves the chain isn't just
        // "regex got lucky two hops away" — there's genuinely nothing to
        // pattern-match on in this file.
        return customerRepository.findByName(query);
    }
}
