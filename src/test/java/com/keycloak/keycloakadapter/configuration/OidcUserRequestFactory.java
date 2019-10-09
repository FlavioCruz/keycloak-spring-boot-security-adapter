package com.keycloak.keycloakadapter.configuration;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

@Component
public class OidcUserRequestFactory {

//    @Bean
//    public KeycloakOauth2UserService keycloakOauth2UserService(){
//        OAuth2ClientProperties oAuth2ClientProperties = new OAuth2ClientProperties();
//        configureOAuth2ClientProperties(oAuth2ClientProperties);
//
//        return new KeycloakOauth2UserService(
//                oAuth2ClientProperties,
//                userDetailsService,
//                Arrays.asList(new MockAuthoritiesProvider())
//        );
//    }
//
//    private void configureOAuth2ClientProperties(OAuth2ClientProperties oAuth2ClientProperties) {
//        OAuth2ClientProperties.Provider provider = new OAuth2ClientProperties.Provider();
//        provider.setAuthorizationUri("authorization-uri");
//        provider.setIssuerUri("/issue/uri");
//        provider.setJwkSetUri("/jwt/uri");
//        provider.setTokenUri("/token/uri");
//        provider.setUserInfoAuthenticationMethod("user-info-authentication-method");
//        provider.setUserInfoUri("user-uri-info");
//        provider.setUserNameAttribute("preferred_username");
//        oAuth2ClientProperties.getProvider().put("keycloak", provider);
//    }

    public OidcUserRequest oidcUserRequest(){
        return new OidcUserRequest(
                clientRegistration(),
                oAuth2AccessTokens(),
                oidcIdTokens()
        );
    }

    public OAuth2AccessToken oAuth2AccessTokens(){
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJxaUFIdEw4UklxRm40RFNQdUJrRlpyaVo5N" +
                        "DJzSzU3dFhlSUkxYVltbjZ3In0.eyJqdGkiOiIwYWY1NmUzNi1kODBiLTRhMzEtYTBkNS0zMjliM2MzMGVjMWQi" +
                        "LCJleHAiOjE1Njk4NzcyOTQsIm5iZiI6MCwiaWF0IjoxNTY5ODc2OTk0LCJpc3MiOiJodHRwOi8vbG9jYWxob3N" +
                        "0OjgwODAvYXV0aC9yZWFsbXMvU3ByaW5nQm9vdEtleWNsb2FrIiwic3ViIjoiMzBhYWE3NWEtZTAzZC00MWY5LW" +
                        "JmZjUtN2YyNWRmZDBkOWJlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoicmFkIiwiYXV0aF90aW1lIjoxNTY5ODc2O" +
                        "Tk0LCJzZXNzaW9uX3N0YXRlIjoiNjBkOTQ0YzctMWQzOS00MTc4LWI3MWQtNDkyZTdkNmVkYWU1IiwiYWNyIjoi" +
                        "MSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vbG9jYWxob3N0OjgwODEiXSwicmVzb3VyY2VfYWNjZXNzIjp" +
                        "7InJhZCI6eyJyb2xlcyI6WyJnZXJlbnRlIl19fSwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSIsImVtYW" +
                        "lsX3ZlcmlmaWVkIjpmYWxzZSwidXNlcl9uYW1lIjoiMTE0NDE4MjE3NDAiLCJuYW1lIjoiTWFyY29zIENvcnRlc" +
                        "yIsInByZWZlcnJlZF91c2VybmFtZSI6IjExNDQxODIxNzQwIiwiZ2l2ZW5fbmFtZSI6Ik1hcmNvcyIsImZhbWls" +
                        "eV9uYW1lIjoiQ29ydGVzIn0.Xa9RS3l3y7OWn3wOI8joVWgjpOVa3GkFW74GZj-gVd87hKwxI1RIz6ogYPZOB9j" +
                        "VmIqFm2MR7khxXlUZfMoSUuItl9mb_sZjM20X2EMOLcD-KStIrEZ46q5-Xiws79r7q68jquoA-_e_nAEGZimRGC" +
                        "ZNsBT3RTwDfQcphHX2mdigZpeaMiI7yK_PIkxn086SizR-iat6YlPNanC1krPj94IRF1_7GttS0myy2OcQsJcps" +
                        "fUNMn3qZRNPlUKQf2fYwd-Hvd49HLOi6SzRz9CPtJbJ61uimXoTrylJBk49RiurJdH7NVEUk_dch0Qg2ifOru_Z" +
                        "Yde8okf9RHY8h5dLAQ",
                Instant.now(),
                Instant.now()
        );
    }

    public OidcIdToken oidcIdTokens(){
        return new OidcIdToken(
                "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJxaUFIdEw4UklxRm40RFNQdUJrRlpyaVo5N" +
                        "DJzSzU3dFhlSUkxYVltbjZ3In0.eyJqdGkiOiIwYWY1NmUzNi1kODBiLTRhMzEtYTBkNS0zMjliM2MzMGVjMWQi" +
                        "LCJleHAiOjE1Njk4NzcyOTQsIm5iZiI6MCwiaWF0IjoxNTY5ODc2OTk0LCJpc3MiOiJodHRwOi8vbG9jYWxob3N" +
                        "0OjgwODAvYXV0aC9yZWFsbXMvU3ByaW5nQm9vdEtleWNsb2FrIiwic3ViIjoiMzBhYWE3NWEtZTAzZC00MWY5LW" +
                        "JmZjUtN2YyNWRmZDBkOWJlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoicmFkIiwiYXV0aF90aW1lIjoxNTY5ODc2O" +
                        "Tk0LCJzZXNzaW9uX3N0YXRlIjoiNjBkOTQ0YzctMWQzOS00MTc4LWI3MWQtNDkyZTdkNmVkYWU1IiwiYWNyIjoi" +
                        "MSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vbG9jYWxob3N0OjgwODEiXSwicmVzb3VyY2VfYWNjZXNzIjp" +
                        "7InJhZCI6eyJyb2xlcyI6WyJnZXJlbnRlIl19fSwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSIsImVtYW" +
                        "lsX3ZlcmlmaWVkIjpmYWxzZSwidXNlcl9uYW1lIjoiMTE0NDE4MjE3NDAiLCJuYW1lIjoiTWFyY29zIENvcnRlc" +
                        "yIsInByZWZlcnJlZF91c2VybmFtZSI6IjExNDQxODIxNzQwIiwiZ2l2ZW5fbmFtZSI6Ik1hcmNvcyIsImZhbWls" +
                        "eV9uYW1lIjoiQ29ydGVzIn0.Xa9RS3l3y7OWn3wOI8joVWgjpOVa3GkFW74GZj-gVd87hKwxI1RIz6ogYPZOB9j" +
                        "VmIqFm2MR7khxXlUZfMoSUuItl9mb_sZjM20X2EMOLcD-KStIrEZ46q5-Xiws79r7q68jquoA-_e_nAEGZimRGC" +
                        "ZNsBT3RTwDfQcphHX2mdigZpeaMiI7yK_PIkxn086SizR-iat6YlPNanC1krPj94IRF1_7GttS0myy2OcQsJcps" +
                        "fUNMn3qZRNPlUKQf2fYwd-Hvd49HLOi6SzRz9CPtJbJ61uimXoTrylJBk49RiurJdH7NVEUk_dch0Qg2ifOru_Z" +
                        "Yde8okf9RHY8h5dLAQ",
                Instant.now(),
                Instant.now(),
                Map.of("preferred_username", "Value")
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

    public OidcUserInfo oidcUserInfo(){
        return new OidcUserInfo(
                Map.of("sub", "Value")
        );
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
