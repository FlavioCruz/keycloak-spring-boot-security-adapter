package com.keycloak.keycloakteste.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.web.client.RestTemplate;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

@Configuration
@AutoConfigureAfter(value = WebMvcAutoConfiguration.class)
@EnableGlobalMethodSecurity(prePostEnabled = true)
//@ConditionalOnBean(value = RestTemplate.class)
@Slf4j
class WebSecurityConfig extends WebSecurityConfigurerAdapter{

    private KeycloakLogoutHandler keycloakLogoutHandler = keycloakLogoutHandler();
    @Autowired
    KeycloakOauth2UserService keycloakOidcUserService;

    @Value("${keycloak.realm}") private String realm;

//    public WebSecurityConfigurerAdapter webSecurityConfigurer( //
//                               @Value("${keycloak.realm}") String realm, //
//                               KeycloakOauth2UserService keycloakOidcUserService, //
//                               KeycloakLogoutHandler keycloakLogoutHandler //
//    ) {
//        return new WebSecurityConfigurerAdapter() {
            @Override
            public void configure(HttpSecurity http) throws Exception {

                http
                        //Configura o gerenciamento da sessão conforme suas necessidades.
                        // I need this as a basis for a classic, server side rendered application
                        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED).and()
                        // Aqui pode ser configuradas rotas específicas ou deixar passar tudo
                        .authorizeRequests().anyRequest().permitAll().and()
                        // Utiliza o logout do Keycloak
                        .logout().addLogoutHandler(keycloakLogoutHandler).and()
                        // Habilita o OAuth 2 do Spring
                        .oauth2Login().userInfoEndpoint().oidcUserService(keycloakOidcUserService).and()
                        // Redireciona a página de login para a do Keycloak
                        .loginPage(DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/" + realm);
            }
//        };
//    }

    public KeycloakOauth2UserService keycloakOidcUserService(OAuth2ClientProperties oauth2ClientProperties) {
        JwtDecoder jwtDecoder = jwtDecoder(oauth2ClientProperties);

        SimpleAuthorityMapper authoritiesMapper = new SimpleAuthorityMapper();
        authoritiesMapper.setConvertToUpperCase(true);

        return new KeycloakOauth2UserService(jwtDecoder, authoritiesMapper);
    }

    public KeycloakLogoutHandler keycloakLogoutHandler() {
        return new KeycloakLogoutHandler(restTemplate());
    }

    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    public JwtDecoder jwtDecoder(OAuth2ClientProperties oauth2ClientProperties) {
        return new NimbusJwtDecoderJwkSupport(oauth2ClientProperties.getProvider().get("keycloak").getJwkSetUri());
    }
}
