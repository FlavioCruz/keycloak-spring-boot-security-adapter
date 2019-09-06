package com.keycloak.keycloakteste.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/keycloak-teste")
@PreAuthorize("hasAnyAuthority('ROLE_USER')")
public class ApiController {

    @GetMapping
    public String teste(Model model){
        model.addAttribute("username", "flavio");
        model.addAttribute("variavel", "hehe");
        return "customers";
    }
}
