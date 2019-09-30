package com.keycloak.keycloakteste.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@Service
public class KeycloakOauth2UserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final OAuth2Error INVALID_REQUEST = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);

    private final OidcUserService oidcUserService;

    private final JwtDecoder jwtDecoder;

    private final GrantedAuthoritiesMapper authoritiesMapper;

    private final List<ApplicationAuthoritiesProvider> applicationAuthoritiesProviders;

    public KeycloakOauth2UserService(OAuth2ClientProperties oauth2ClientProperties,
                                     OidcUserService oidcUserService,
                                     List<ApplicationAuthoritiesProvider> applicationAuthoritiesProviders){
        this.jwtDecoder = new NimbusJwtDecoderJwkSupport(
                oauth2ClientProperties
                        .getProvider()
                        .get("keycloak")
                        .getJwkSetUri()
        );

        this.applicationAuthoritiesProviders = applicationAuthoritiesProviders;

        SimpleAuthorityMapper authoritiesMapper = new SimpleAuthorityMapper();
        authoritiesMapper.setConvertToUpperCase(true);
        this.authoritiesMapper = authoritiesMapper;

        this.oidcUserService =  oidcUserService;
    }

    /**
     * Augments {@link OidcUserService#loadUser(OidcUserRequest)} to add authorities
     * provided by Keycloak.
     *
     * Needed because {@link OidcUserService#loadUser(OidcUserRequest)} (currently)
     * does not provide a hook for adding custom authorities from a
     * {@link OidcUserRequest}.
     */
    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

        OidcUser user = oidcUserService.loadUser(userRequest);

        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        authorities.addAll(user.getAuthorities());
        authorities.addAll(this.findApplicationAuthorities(user));
        authorities.addAll(extractKeycloakAuthorities(userRequest));

        return new DefaultOidcUser(authorities, userRequest.getIdToken(), user.getUserInfo(), "preferred_username");
    }

    private Collection<? extends GrantedAuthority> findApplicationAuthorities(OidcUser user) {
        return this.applicationAuthoritiesProviders
                .stream()
                .flatMap(x->x.findAuthorities(user).stream())
                .collect(Collectors.toList());
    }

    /**
     * Extracts {@link GrantedAuthority GrantedAuthorities} from the AccessToken in
     * the {@link OidcUserRequest}.
     *
     * @param userRequest
     * @return
     */
    private Collection<? extends GrantedAuthority> extractKeycloakAuthorities(OidcUserRequest userRequest) {

        return OidcUserRequestAuthoritiesExtractor.extract(userRequest, authoritiesMapper, this::parseJwt);

        // Would be great if Spring Security would provide something like a plugable
        // OidcUserRequestAuthoritiesExtractor interface to hide the junk below...
    }

    private Jwt parseJwt(String accessTokenValue) {
        try {
            // Token is already verified by spring security infrastructure
            return jwtDecoder.decode(accessTokenValue);
        } catch (JwtException e) {
            throw new OAuth2AuthenticationException(INVALID_REQUEST, e);
        }
    }
}
