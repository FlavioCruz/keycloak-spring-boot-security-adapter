package com.keycloak.keycloakteste.configuration.entity;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class KeycloakTokens {
    private String accessToken;
    private String refreshToken;
}
