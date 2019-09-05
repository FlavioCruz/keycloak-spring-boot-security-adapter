package com.keycloak.keycloakteste.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping(value = "/teste")
    @PreAuthorize("hasAnyAuthority('ROLE_USUARIO')")
    public String teste(){
        return "teste";
    }
}
