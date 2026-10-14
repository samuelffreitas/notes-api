package pt.samuel.notes_api.controlers;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// Endpoint de diagnóstico: mostra o que o token produziu depois da conversão.
// Não tem @PreAuthorize de propósito — se a conversão das roles falhar, é aqui
// que se vê porquê, e um hasRole() aqui esconderia o problema.
@RestController
public class DiagnosticoController {

    @GetMapping("/me")
    public Map<String, Object> me(JwtAuthenticationToken autenticacao) {
        Map<String, Object> resposta = new LinkedHashMap<>();
        resposta.put("sub", autenticacao.getToken().getSubject());
        resposta.put("teams", autenticacao.getToken().getClaimAsStringList("teams"));
        resposta.put("realm_access", autenticacao.getToken().getClaimAsMap("realm_access"));
        resposta.put("authorities", autenticacao.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList());
        return resposta;
    }
}
