package com.keycloak.keycloakteste.configuration;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

public class OidcUserRequestAuthoritiesExtractor {

    public static Collection<? extends GrantedAuthority> extract(OidcUserRequest userRequest, GrantedAuthoritiesMapper authoritiesMapper, Function<String, Jwt> jwtParser){

        Jwt token = jwtParser.apply(userRequest.getAccessToken().getTokenValue());

        @SuppressWarnings("unchecked")
        Map<String, Object> resourceMap = (Map<String, Object>) token.getClaims().get("resource_access");
        String clientId = userRequest.getClientRegistration().getClientId();

        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> clientResource = (Map<String, Map<String, Object>>) resourceMap.get(clientId);
        if (CollectionUtils.isEmpty(clientResource)) {
            return Collections.emptyList();
        }

        @SuppressWarnings("unchecked")
        List<String> clientRoles = (List<String>) clientResource.get("roles");
        if (CollectionUtils.isEmpty(clientRoles)) {
            return Collections.emptyList();
        }

        Collection<? extends GrantedAuthority> authorities = AuthorityUtils
                .createAuthorityList(clientRoles.toArray(new String[0]));
        if (authoritiesMapper == null) {
            return authorities;
        }

        return authoritiesMapper.mapAuthorities(authorities);
    }
}
