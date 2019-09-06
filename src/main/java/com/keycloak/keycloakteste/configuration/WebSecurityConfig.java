package com.keycloak.keycloakteste.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.web.client.RestTemplate;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
class WebSecurityConfig {

    @Bean
    public WebSecurityConfigurerAdapter webSecurityConfigurer( //
                               @Value("${keycloak.realm}") String realm, //
                               KeycloakOauth2UserService keycloakOidcUserService, //
                               KeycloakLogoutHandler keycloakLogoutHandler //
    ) {
        return new WebSecurityConfigurerAdapter() {
            @Override
            public void configure(HttpSecurity http) throws Exception {

                http
                        // Configure session management to your needs.
                        // I need this as a basis for a classic, server side rendered application
                        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED).and()
                        // Depends on your taste. You can configure single paths here
                        // or allow everything a I did and then use method based security
                        // like in the controller below
                        .authorizeRequests().anyRequest().permitAll().and()
                        // Propagate logouts via /logout to Keycloak
                        .logout().addLogoutHandler(keycloakLogoutHandler).and()
                        // This is the point where OAuth2 login of Spring 5 gets enabled
                        .oauth2Login().userInfoEndpoint().oidcUserService(keycloakOidcUserService).and()
                        // I don't want a page with different clients as login options
                        // So i use the constant from OAuth2AuthorizationRequestRedirectFilter
                        // plus the configured realm as immediate redirect to Keycloak
                        .loginPage(DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/" + realm);
            }
        };
    }

    @Bean
    public KeycloakOauth2UserService keycloakOidcUserService(OAuth2ClientProperties oauth2ClientProperties) {

        NimbusJwtDecoderJwkSupport jwtDecoder = new NimbusJwtDecoderJwkSupport(
                oauth2ClientProperties.getProvider().get("keycloak").getJwkSetUri());

        SimpleAuthorityMapper authoritiesMapper = new SimpleAuthorityMapper();
        authoritiesMapper.setConvertToUpperCase(true);

        return new KeycloakOauth2UserService(jwtDecoder, authoritiesMapper);
    }

    @Bean
    public KeycloakLogoutHandler keycloakLogoutHandler() {
        return new KeycloakLogoutHandler(new RestTemplate());
    }
}
