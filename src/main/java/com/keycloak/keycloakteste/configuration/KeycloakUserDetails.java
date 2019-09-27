/**
 * @author FlavioCruz
 *
 * This class aims to simulate the logged user and
 * keeps the OidcIdToken
 */


package com.keycloak.keycloakteste.configuration;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
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

    private KeycloakUserDetails(){    }

    protected KeycloakUserDetails(DefaultOidcUser user) {
        super();
        this.username = user.getPreferredUsername();
        this.claims = user.getClaims();
        this.userInfo = user.getUserInfo();
        this.idToken = user.getIdToken();
        this.attributes = user.getAttributes();
        this.name = user.getName();
    }

    @SuppressWarnings("unchecked")
    public static <T extends KeycloakUserDetails> T createUser(Object user){
        if(user.getClass().isAssignableFrom(UserDetails.class)){
            KeycloakUserDetails userKeycloak = new KeycloakUserDetails();
            var userDetails = (UserDetails) user;
            userKeycloak.authorities = userDetails.getAuthorities();
            userKeycloak.username = userDetails.getUsername();
            return (T) userKeycloak;
        }
        return (T) (user.getClass().isAssignableFrom(DefaultOidcUser.class) ?
                 new KeycloakUserDetails((DefaultOidcUser) user) :
                 user);
    }
}
