package com.keycloak.keycloakadapter.configuration;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mockito;
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

import java.util.Arrays;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMapOf;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;

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
        DefaultOidcUser userMockado = new DefaultOidcUser(
                Arrays.asList(new SimpleGrantedAuthority("role")),
                factory.oidcIdTokens(),
                factory.oidcUserInfo(),
                "sub"
        );
        doReturn(userMockado).when(authentication).getPrincipal();
        RestTemplate restTemplateMockado = mock(RestTemplate.class);
        ResponseEntity<String> responseEntity = new ResponseEntity<String>(HttpStatus.OK);
        ReflectionTestUtils.setField(keycloakLogoutHandler, "restTemplate", restTemplateMockado);
        doReturn(responseEntity)
                .when(restTemplateMockado)
                .getForEntity(
                        anyString(),
                        any(),
                        anyMapOf(String.class, String.class)
                );

        keycloakLogoutHandler.logout(request, null, authentication);

        InOrder inOrder = Mockito.inOrder(
                authentication,
                restTemplateMockado
        );
        inOrder.verify(authentication, times(2)).getPrincipal();
        inOrder.verify(restTemplateMockado).getForEntity(
                anyString(),
                any(),
                anyMapOf(String.class, String.class)
        );
        inOrder.verifyNoMoreInteractions();
    }
}