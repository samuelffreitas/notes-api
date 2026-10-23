package pt.samuel.notes_api.security;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

// Converte as roles de realm_access.roles em authorities com prefixo ROLE_.
// Sem esta conversão, o hasRole('app-user') nunca passa.

public class KeycloakRolesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    // Corre uma vez por pedido, sobre o token já validado.
    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        // Lê a claim realm_access, onde o Keycloak põe as roles do realm.
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        // Token sem essa claim fica sem authorities nenhumas.
        if (realmAccess == null) {
            return List.of();
        }
        // O mesmo se o "roles" lá dentro não for uma coleção.
        if (!(realmAccess.get("roles") instanceof Collection<?> roles)) {
            return List.of();
        }
        // Prefixa cada role com ROLE_, que é o que o Spring Security espera.
        return roles.stream()
                .map(String::valueOf)
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role))
                .toList();
    }
}
