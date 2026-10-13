package pt.samuel.notes_api.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

// Existe porque o Spring confere o iss e o exp, mas não o aud.
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private static final Logger log = LoggerFactory.getLogger(AudienceValidator.class);

    private final String audienciaEsperada;

    public AudienceValidator(String audienciaEsperada) {
        this.audienciaEsperada = audienciaEsperada;
    }

    // Recebe um token já descodificado, olha para o aud, devolve sucesso ou
    // falha. Não devolve 401, não escreve resposta nenhuma — só dá um veredito.
    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        if (jwt.getAudience() != null && jwt.getAudience().contains(audienciaEsperada)) {
            return OAuth2TokenValidatorResult.success();
        }

        log.warn("aud invalida: esperado '{}', recebido {} (sub={})",
                audienciaEsperada, jwt.getAudience(), jwt.getSubject());

        return OAuth2TokenValidatorResult.failure(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "audiencia invalida", null));
    }
}
