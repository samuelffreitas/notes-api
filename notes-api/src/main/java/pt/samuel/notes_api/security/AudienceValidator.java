package pt.samuel.notes_api.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

// Valida o aud dos tokens, que os validadores por omissão do resource server
// não conferem. Devolve só um veredito; a resposta ao cliente é de outro.

public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    // Logger deste validador.
    private static final Logger log = LoggerFactory.getLogger(AudienceValidator.class);

    // Audiência exigida, vinda do application.yml.
    private final String audienciaEsperada;

    // Recebe a audiência esperada quando o bean do JwtDecoder o constrói.
    public AudienceValidator(String audienciaEsperada) {
        this.audienciaEsperada = audienciaEsperada;
    }

    // Corre sobre um token já descodificado e com a assinatura verificada.
    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        // Aceita se o aud existir e contiver a audiência esperada.
        if (jwt.getAudience() != null && jwt.getAudience().contains(audienciaEsperada)) {
            return OAuth2TokenValidatorResult.success();
        }

        // Escreve o motivo no log do servidor, que a resposta ao cliente não revela.
        log.warn("aud invalida: esperado '{}', recebido {} (sub={})",
                audienciaEsperada, jwt.getAudience(), jwt.getSubject());

        // Devolve falha, que o decoder transforma num token inválido.
        return OAuth2TokenValidatorResult.failure(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "audiencia invalida", null));
    }
}
