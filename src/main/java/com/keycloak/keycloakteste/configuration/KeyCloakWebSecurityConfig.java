package com.keycloak.keycloakteste.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

@Slf4j
public class KeyCloakWebSecurityConfig extends WebSecurityConfigurerAdapter{

    @Autowired
    private KeycloakOauth2UserService keycloakOidcUserService;

    @Autowired
    private KeycloakProperties keycloakProperties;
    @Override
    public void configure(HttpSecurity http) throws Exception {

        http
                //Configura o gerenciamento da sessão conforme suas necessidades.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED).and()
                // Aqui pode ser configuradas rotas específicas ou deixar passar tudo
                .authorizeRequests().anyRequest().permitAll().and()
                // Habilita o OAuth 2 do Spring
                .oauth2Login().userInfoEndpoint().oidcUserService(keycloakOidcUserService).and()
                // Redireciona a página de login para a do Keycloak
                .loginPage(DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/" + keycloakProperties.getRealm())
                // Redireciona para a página de logout do Keycloak
                .and().logout().addLogoutHandler(keycloakLogoutHandler());
    }

    public KeycloakLogoutHandler keycloakLogoutHandler() {
        return new KeycloakLogoutHandler(keycloakProperties.getRealmUrl());
    }

}
