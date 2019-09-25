/**
 *
 * @author FlavioCruz
 *
 * This class looks for the base configuration for the keycloak server
 * within the 'keycloak' prefix over the configuration file.
 *
 * e.g.
 *      application.properties
 *      keycloak.base-url=http://www.example.com/
 *      keycloak.real=RealmName
 *
 *      application.yml
 *      keycloak:
 *          base-url: http://www.example.com/
 *          realm: RealmName
 */



package com.keycloak.keycloakteste.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "keycloak")
public class KeycloakProperties {
    private String baseUrl;
    private String realm;
    private String realmUrl;
}
