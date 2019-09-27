package com.keycloak.keycloakteste.configuration;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.jupiter.api.Assertions.*;

@RunWith(SpringRunner.class)
//@SpringBootTest(properties = {"src/"})
public class KeycloakOauth2UserServiceTest {

//    @Autowired
    private SecurityTestConfig securityTestConfig = new SecurityTestConfig();

    @Test
    public void loadUser() {

        securityTestConfig.keycloakOauth2UserService().loadUser(
                new OidcUserRequest(
                        securityTestConfig.clientRegistration(),
                        securityTestConfig.oAuth2AccessTokens(),
                        securityTestConfig.oidcIdTokens()
                )
        );
    }
}