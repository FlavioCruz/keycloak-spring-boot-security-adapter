package com.keycloak.keycloakteste.controller;

import org.keycloak.KeycloakSecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/login")
public class WebController {

    @Autowired
    private HttpServletRequest request;

    @GetMapping(path = "/")
    public String index(){
        return "external";
    }

    @GetMapping(path = "/customers")
    public String customers(Model model){
        model.addAttribute("variavel", "Keycloak works!!!");
        return "customers";
    }

    private KeycloakSecurityContext getKeycloakContext(){
        return (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
    }
}
