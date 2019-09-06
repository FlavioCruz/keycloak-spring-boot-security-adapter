package com.keycloak.keycloakteste;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

@SpringBootApplication
public class KeycloakTesteApplication extends SpringBootServletInitializer {

	public static void main(String[] args) {
		SpringApplication.run(KeycloakTesteApplication.class, args);
	}

}
