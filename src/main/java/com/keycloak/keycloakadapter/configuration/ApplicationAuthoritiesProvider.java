package com.keycloak.keycloakadapter.configuration;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;

public interface ApplicationAuthoritiesProvider {
    <T extends OidcUser> Collection<? extends GrantedAuthority> findAuthorities( T user);
}
