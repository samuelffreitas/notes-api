package pt.samuel.notes_api.security;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

// Valida o azp, a claim que diz qual o cliente que pediu o token. Recusa
// tokens de clientes desconhecidos, mesmo com aud e assinatura corretos.

public class AzpValidator implements OAuth2TokenValidator<Jwt> {

    // Logger deste validador.
    private static final Logger log = LoggerFactory.getLogger(AzpValidator.class);

    // Lista branca de clientes, vinda do application.yml.
    private final List<String> clientesPermitidos;

    // Recebe a lista quando o bean do JwtDecoder o constrói.
    public AzpValidator(List<String> clientesPermitidos) {
        this.clientesPermitidos = clientesPermitidos;
    }

    // Corre sobre um token já descodificado e com a assinatura verificada.
    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        // Cliente que pediu este token ao Keycloak.
        String azp = jwt.getClaimAsString("azp");

        // Aceita só se o azp existir e constar da lista branca.
        if (azp != null && clientesPermitidos.contains(azp)) {
            return OAuth2TokenValidatorResult.success();
        }

        // Escreve o motivo no log do servidor, que a resposta ao cliente não revela.
        log.warn("azp invalido: recebido '{}', permitidos {} (sub={})",
                azp, clientesPermitidos, jwt.getSubject());

        // Devolve falha, que o decoder transforma num token inválido.
        return OAuth2TokenValidatorResult.failure(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "cliente nao autorizado", null));
    }
}
