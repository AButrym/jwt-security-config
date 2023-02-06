package com.example.demo.controller;

import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class EchoController {
    @GetMapping("/echo")
    String echoGet(@RequestParam Map<String, String> params) {
        return "Hello! The params are: " + params;
    }

    @PostMapping("/echo")
    String echoPost(@RequestBody String body) {
        return body;
    }
}
