keycloak:
#  base-url: http://200.20.1.158:8080/auth
  base-url: http://localhost:8080/auth
  realm: SpringBootKeycloak
  realm-url: ${keycloak.base-url}/realms/${keycloak.realm}

spring:
  security:
    oauth2:
      client:
        registration:
          SpringBootKeycloak:
            client-id: client-id
            client-name: client name
            client-secret: 61b4bff5-328f-4811-99ad-32cc06476d13
            provider: keycloak
            authorization-grant-type: authorization_code
            scope: openid, profile
            redirect-uri-template: "{baseUrl}/login/oauth2/code/{registrationId}"
        provider:
          keycloak:
            authorization-uri: ${keycloak.realm-url}/protocol/openid-connect/auth
            jwk-set-uri: ${keycloak.realm-url}/protocol/openid-connect/certs
            token-uri: ${keycloak.realm-url}/protocol/openid-connect/token
            # would be cool if there was a end-session-uri to propagate logouts

            #  User info endpoint not needed since Keycloak uses self-contained value tokens
            #            user-info-uri: ${keycloak.realm-url}/protocol/openid-connect/userinfo
            user-name-attribute: preferred_username