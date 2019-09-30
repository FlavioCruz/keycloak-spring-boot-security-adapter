package com.keycloak.keycloakteste.configuration;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Arrays;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

@RunWith(SpringRunner.class)
@SpringBootTest
public class KeycloakLogoutHandlerTest {

    @Autowired
    private KeycloakProperties keycloakProperties;

    @Autowired
    private OidcUserRequestFactory factory;

    @Test
    public void logout(){

        KeycloakLogoutHandler keycloakLogoutHandler = new KeycloakLogoutHandler(keycloakProperties.getRealmUrl());

        HttpServletRequest request = mock(HttpServletRequest.class);
        doReturn(null).when(request).getSession(false);

        Authentication authentication = mock(Authentication.class);
        doReturn(new DefaultOidcUser(Arrays.asList(new SimpleGrantedAuthority("role")), factory.oidcIdTokens()));

        keycloakLogoutHandler.logout(request, null, null);


    }

}