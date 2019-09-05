package com.keycloak.keycloakteste.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keycloak.keycloakteste.configuration.entity.KeycloakTokens;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
@ConditionalOnProperty(prefix = "rest.security", value = "enabled", havingValue = "true")
@Import({SecurityProperties.class})
public class SecurityConfigurer extends ResourceServerConfigurerAdapter {

    private static final Logger LOG = LoggerFactory.getLogger(SecurityConfigurer.class);

    @Autowired
    private ResourceServerProperties resourceServerProperties;

    @Autowired
    private SecurityProperties securityProperties;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId(resourceServerProperties.getResourceId());
    }


    @Override
    public void configure(final HttpSecurity http) throws Exception {

        http.cors()
                .configurationSource(corsConfigurationSource())
                .and()
                .headers()
                .frameOptions()
                .disable()
                .and()
                .csrf()
                .disable()
                .authorizeRequests()
                .antMatchers(securityProperties.getApiMatcher())
                .authenticated();

    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        if (null != securityProperties.getCorsConfiguration()) {
            source.registerCorsConfiguration("/**", securityProperties.getCorsConfiguration());
        }
        return source;
    }

    @Bean
    public JwtAccessTokenCustomizer jwtAccessTokenCustomizer(ObjectMapper mapper) {
        return new JwtAccessTokenCustomizer(mapper);
    }

    @Bean
    public OAuth2RestTemplate oauth2RestTemplate(OAuth2ProtectedResourceDetails details) {
        LOG.info(
                "{} info: ApiMatcher -> {}   |   IssueURI -> {}",
                SecurityProperties.class.getSimpleName(),
                securityProperties.getApiMatcher(),
                securityProperties.getIssuerUri()
        );

        LOG.info(
                "{} info: Id -> {}, ClientId -> {}   |   AccessTokenUri -> {}",
                SecurityConfigurer.class.getSimpleName(),
                details.getId(),
                details.getClientId(),
                details.getAccessTokenUri()
        );

        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(details);

        LOG.info(
                "{} info: OAuth2ClientContextURI -> {}   |   ClientId -> {}",
                OAuth2RestTemplate.class.getSimpleName(),
                oAuth2RestTemplate.getOAuth2ClientContext().getAccessTokenRequest().getCurrentUri(),
                oAuth2RestTemplate.getResource().getClientId()
        );

        //Prepare by getting access token once
        oAuth2RestTemplate.getAccessToken();

        LOG.info("AccessToken -> {}", oAuth2RestTemplate.getAccessToken().getValue());

        return oAuth2RestTemplate;
    }

//    private KeycloakTokens retrieveAuthorizationTokens(){
//
//    }
}
