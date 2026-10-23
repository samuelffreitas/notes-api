package pt.samuel.notes_api.controlers;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// Endpoint /me, que mostra o que o token produziu depois da conversão das
// roles. Serve para diagnosticar autorização e não faz parte do domínio.

// Expõe a classe como controller REST.
@RestController
public class DiagnosticoController {

    // GET /me: sem @PreAuthorize de propósito, para um token sem roles chegar aqui.
    @GetMapping("/me")
    public Map<String, Object> me(JwtAuthenticationToken autenticacao) {
        // Mapa que preserva a ordem de inserção na resposta JSON.
        Map<String, Object> resposta = new LinkedHashMap<>();
        // O sub do token, que identifica o dono das notas.
        resposta.put("sub", autenticacao.getToken().getSubject());
        // A claim teams, injetada pelo mapper de grupos do Keycloak.
        resposta.put("teams", autenticacao.getToken().getClaimAsStringList("teams"));
        // As roles como vêm no token, antes de qualquer conversão.
        resposta.put("realm_access", autenticacao.getToken().getClaimAsMap("realm_access"));
        // As authorities que o KeycloakRolesConverter produziu a partir delas.
        resposta.put("authorities", autenticacao.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList());
        // Devolve o mapa, que o Spring serializa em JSON.
        return resposta;
    }
}
