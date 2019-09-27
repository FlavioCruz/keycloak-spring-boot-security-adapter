package com.keycloak.keycloakteste.configuration;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@Component
@TestConfiguration
public class SecurityTestConfig {

    @MockBean
    private OidcUserService userDetailsService;

    @Bean
    public KeycloakOauth2UserService keycloakOauth2UserService(){
        OAuth2ClientProperties oAuth2ClientProperties = new OAuth2ClientProperties();
        configureOAuth2ClientProperties(oAuth2ClientProperties);

        return new KeycloakOauth2UserService(
                oAuth2ClientProperties,
                userDetailsService,
                Arrays.asList(new MockAuthoritiesProvider())
        );
    }

    private void configureOAuth2ClientProperties(OAuth2ClientProperties oAuth2ClientProperties) {
        OAuth2ClientProperties.Provider provider = new OAuth2ClientProperties.Provider();
        provider.setAuthorizationUri("authorization-uri");
        provider.setIssuerUri("issue-uri");
        provider.setJwkSetUri("jwk-set-uri");
        provider.setTokenUri("token-uri");
        provider.setUserInfoAuthenticationMethod("user-info-authentication-method");
        provider.setUserInfoUri("user-uri-info");
        provider.setUserNameAttribute("preferred_username");
        oAuth2ClientProperties.getProvider().put("keycloak", provider);
    }

    public OAuth2AccessToken oAuth2AccessTokens(){
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "token",
                Instant.now(),
                Instant.now()
        );
    }

    public OidcIdToken oidcIdTokens(){
        return new OidcIdToken(
                "token",
                Instant.now(),
                Instant.now(),
                (Map<String, Object>) new HashMap<>().put("Claim", "Value")
        );
    }

    public ClientRegistration clientRegistration(){
        return ClientRegistration.withRegistrationId("registered")
                .authorizationGrantType(new AuthorizationGrantType("authorization_code"))
                .clientId("clientId")
                .redirectUriTemplate("template")
                .authorizationUri("authorization")
                .tokenUri("token uri")
                .build();
    }


    private class MockAuthoritiesProvider implements ApplicationAuthoritiesProvider{

        @Override
        public <T extends OidcUser> Collection<? extends GrantedAuthority> findAuthorities(T user) {
            return Arrays.asList(
                    new SimpleGrantedAuthority("manager"),
                    new SimpleGrantedAuthority("user")
            );
        }
    }
}
