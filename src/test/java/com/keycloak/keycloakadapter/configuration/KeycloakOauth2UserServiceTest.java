package com.keycloak.keycloakadapter.configuration;

import lombok.val;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static java.util.stream.Collectors.toList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

@RunWith(SpringRunner.class)
@SpringBootTest
public class KeycloakOauth2UserServiceTest {

    public static class ApplicationAuthoritiesProviderParaTeste implements ApplicationAuthoritiesProvider{
        @Override
        public <T extends OidcUser> Collection<? extends GrantedAuthority> findAuthorities(T user) {
            return Collections.emptyList();
        }

    }

    @TestConfiguration
    public static class ApplicationAuthoritiesProviderParaTesteConfiguration{

        @Bean
        public ApplicationAuthoritiesProvider applicationAuthoritiesProviderMockado(){
            return new ApplicationAuthoritiesProviderParaTeste();
        }
    }

    @MockBean
    private OidcUserService oidcUserService;

    @MockBean
    private ApplicationAuthoritiesProviderParaTeste applicationAuthoritiesProviderParaTeste;

    @Autowired
    private ApplicationContext context;

    @Autowired
    private OidcUserRequestFactory oidcUserRequestFactory;

    @Test
    public void loadUser() {

        val oidcUserRequest = oidcUserRequestFactory.oidcUserRequest();

        OidcUser oidcUserMockado = mock(OidcUser.class);

        doReturn(List.of(new SimpleGrantedAuthority("USER"))).when(oidcUserMockado).getAuthorities();
        doReturn(Collections.emptyList())
                .when(applicationAuthoritiesProviderParaTeste)
                .findAuthorities(eq(oidcUserMockado));
        doReturn(oidcUserMockado).when(oidcUserService).loadUser(eq(oidcUserRequest));

        KeycloakOauth2UserService keycloakOauth2UserService = context.getBean(KeycloakOauth2UserService.class);

        JwtDecoder decoderMockado = mock(JwtDecoder.class);
        ReflectionTestUtils.setField(keycloakOauth2UserService, "jwtDecoder", decoderMockado);
        doReturn(
                new Jwt(
                        oidcUserRequest.getAccessToken().getTokenValue(),
                        Instant.now(), Instant.now(),
                        Map.of("roles", Map.of()), //headers
                        Map.of("resource_access", Map.of()) //claims
                )
        ).when(decoderMockado).decode(oidcUserRequest.getAccessToken().getTokenValue());

        OidcUser oidcUser = keycloakOauth2UserService.loadUser(oidcUserRequest);

        InOrder inOrder = Mockito.inOrder(
                applicationAuthoritiesProviderParaTeste,
                oidcUserMockado,
                oidcUserService
        );

        inOrder.verify(oidcUserService).loadUser(eq(oidcUserRequest));
        inOrder.verify(oidcUserMockado).getAuthorities();
        inOrder.verify(applicationAuthoritiesProviderParaTeste).findAuthorities(eq(oidcUserMockado));

        val authorities = oidcUser.getAuthorities().stream().collect(toList());
        assertThat(authorities).hasSize(1);
    }
}