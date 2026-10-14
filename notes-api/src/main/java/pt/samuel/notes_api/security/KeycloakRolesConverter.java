package pt.samuel.notes_api.security;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

// O Keycloak põe as roles em realm_access.roles. O Spring espera authorities
// com prefixo ROLE_. Sem esta conversão, o hasRole('app-user') nunca passa.
public class KeycloakRolesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess == null) {
            return List.of();
        }
        if (!(realmAccess.get("roles") instanceof Collection<?> roles)) {
            return List.of();
        }
        return roles.stream()
                .map(String::valueOf)
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role))
                .toList();
    }
}
