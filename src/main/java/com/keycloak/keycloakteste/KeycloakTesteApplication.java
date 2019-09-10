package com.keycloak.keycloakteste;

import com.keycloak.keycloakteste.configuration.KeycloakOauth2UserService;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
//@ComponentScan(value = {KeycloakOauth2UserService})
public class KeycloakTesteApplication extends SpringBootServletInitializer {

	public static void main(String[] args) {
		SpringApplication.run(KeycloakTesteApplication.class, args);
	}

}
