package com.keycloak.keycloakteste.configuration;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Field;

/**
 * Propagates logouts to Keycloak.
 *
 * Necessary because Spring Security 5 (currently) doesn't support
 * end-session-endpoints.
 */
@Slf4j
@RequiredArgsConstructor
public class KeycloakLogoutHandler extends SecurityContextLogoutHandler {

    private final String issuer;

    private final RestTemplate restTemplate = new RestTemplate();

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        super.logout(request, response, authentication);
        try {
            Field tokenField = authentication.getPrincipal().getClass()
                    .getDeclaredField("idToken");
            tokenField.setAccessible(true);
            OidcIdToken token = (OidcIdToken) tokenField.get(authentication.getPrincipal());
            propagateLogoutToKeycloak(token);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            e.printStackTrace();
        }
    }

    private void propagateLogoutToKeycloak(OidcIdToken token) {

        String endSessionEndpoint =  issuer + "/protocol/openid-connect/logout";

        UriComponentsBuilder builder = UriComponentsBuilder
                .fromUriString(endSessionEndpoint)
                .queryParam("id_token_hint", token.getTokenValue());

        ResponseEntity<String> logoutResponse = restTemplate.getForEntity(builder.toUriString(), String.class);
        if (logoutResponse.getStatusCode().is2xxSuccessful()) {
            log.info("Successfulley logged out in Keycloak");
        } else {
            log.info("Could not propagate logout to Keycloak");
        }
    }
}
