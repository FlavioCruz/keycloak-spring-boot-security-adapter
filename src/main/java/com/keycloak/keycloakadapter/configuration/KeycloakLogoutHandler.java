package com.keycloak.keycloakadapter.configuration;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Field;
import java.util.Map;

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
            propagateLogoutToKeycloak(extractToken(authentication));
        } catch (RuntimeException e) {
            e.printStackTrace();
        }
    }

    private void propagateLogoutToKeycloak(OidcIdToken token) {
        String endSessionEndpoint =  issuer + "/protocol/openid-connect/logout";
        ResponseEntity<String> logoutResponse = restTemplate
                .getForEntity(
                endSessionEndpoint,
                        String.class,
                        Map.of("id_token_hint", token.getTokenValue())
        );
        if (logoutResponse.getStatusCode().is2xxSuccessful()) {
            log.info("Successfulley logged out in Keycloak");
        } else {
            log.warn("Could not propagate logout to Keycloak {}", logoutResponse.getStatusCode());
            throw new RuntimeException();
        }
    }

    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication, String redirectUri) {
        super.logout(request, response, authentication);
        try {
            propagateLogoutToKeycloak(extractToken(authentication), redirectUri);
        } catch (RuntimeException e) {
            e.printStackTrace();
        }
    }

    private void propagateLogoutToKeycloak(OidcIdToken token, String redirectUri) {
        String endSessionEndpoint =  issuer + "/protocol/openid-connect/logout" +
                                              "?post_logout_redirect_uri=" + redirectUri;
        ResponseEntity<String> logoutResponse = restTemplate
                .getForEntity(
                        endSessionEndpoint,
                        String.class,
                        Map.of("id_token_hint", token.getTokenValue())
                );
        if (logoutResponse.getStatusCode().is2xxSuccessful()) {
            log.info("Successfulley logged out in Keycloak");
        } else {
            log.warn("Could not propagate logout to Keycloak {}", logoutResponse.getStatusCode());
            throw new RuntimeException();
        }
    }

    /**
     * I MUST have the OidcIdToken field named as 'idToken' so i don't have to deal with
     * Different objects nested on authentication.getPrincipal()
     * @param authentication
     * @return
     */
    private OidcIdToken extractToken(Authentication authentication){
        try {
            Field tokenField = authentication.getPrincipal()
                    .getClass()
                    .getDeclaredField("idToken");
            tokenField.setAccessible(true);
            return (OidcIdToken) tokenField.get(authentication.getPrincipal());
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
}
