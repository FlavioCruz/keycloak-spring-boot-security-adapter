package com.keycloak.keycloakteste.configuration;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Propagates logouts to Keycloak.
 *
 * Necessary because Spring Security 5 (currently) doesn't support
 * end-session-endpoints.
 */
@Slf4j
@RequiredArgsConstructor
class KeycloakLogoutHandler extends SecurityContextLogoutHandler {

    private final RestTemplate restTemplate;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        super.logout(request, response, authentication);

        propagateLogoutToKeycloak((OidcUser) authentication.getPrincipal());
    }

    private void propagateLogoutToKeycloak(OidcUser user) {

        String endSessionEndpoint = user.getIssuer() + "/protocol/openid-connect/logout";

        UriComponentsBuilder builder = UriComponentsBuilder //
                .fromUriString(endSessionEndpoint) //
                .queryParam("id_token_hint", user.getIdToken().getTokenValue());

        ResponseEntity<String> logoutResponse = restTemplate.getForEntity(builder.toUriString(), String.class);
        if (logoutResponse.getStatusCode().is2xxSuccessful()) {
            log.info("Successfulley logged out in Keycloak");
        } else {
            log.info("Could not propagate logout to Keycloak");
        }
    }
}
