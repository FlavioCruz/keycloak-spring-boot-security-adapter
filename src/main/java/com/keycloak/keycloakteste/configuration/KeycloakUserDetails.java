package com.keycloak.keycloakteste.configuration;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.Map;

@Getter
public class KeycloakUserDetails implements OidcUser{

    private Collection<? extends GrantedAuthority> authorities;
    private String username;
    private Map<String, Object> claims;
    private OidcUserInfo userInfo;
    private OidcIdToken idToken;
    private Map<String, Object> attributes;
    private String name;

    protected KeycloakUserDetails(DefaultOidcUser user) {
        super();
        this.username = user.getPreferredUsername();
        this.claims = user.getClaims();
        this.userInfo = user.getUserInfo();
        this.idToken = user.getIdToken();
        this.attributes = user.getAttributes();
        this.name = user.getName();
    }

    public static <T extends KeycloakUserDetails> T criaInstanciaDeUsuario(Object user){
        return (T) (user.getClass().isAssignableFrom(DefaultOidcUser.class) ?
                 new KeycloakUserDetails((DefaultOidcUser) user) :
                 user);
    }
}
