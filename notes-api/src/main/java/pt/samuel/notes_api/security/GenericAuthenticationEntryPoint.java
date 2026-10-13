package pt.samuel.notes_api.security;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// Chamado só quando algo falha.
public class GenericAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final Logger log = LoggerFactory.getLogger(GenericAuthenticationEntryPoint.class);

    // Duas linhas de destino diferente: o motivo detalhado vai para o log do
    // servidor, a resposta genérica vai para o cliente.
    @Override
    public void commence(HttpServletRequest pedido, HttpServletResponse resposta,
            AuthenticationException excecao) throws IOException {

        log.warn("401 em {} {} -> {}", pedido.getMethod(), pedido.getRequestURI(),
                motivo(excecao));                                        // servidor

        resposta.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        resposta.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        resposta.setContentType(MediaType.APPLICATION_JSON_VALUE);
        resposta.getWriter().write("{\"error\":\"unauthorized\"}");      // cliente
    }

    private String motivo(AuthenticationException excecao) {
        if (excecao instanceof OAuth2AuthenticationException oauth) {
            OAuth2Error erro = oauth.getError();
            String descricao = erro.getDescription();
            return erro.getErrorCode() + (descricao != null ? ": " + descricao : "");
        }
        return excecao.getClass().getSimpleName() + ": " + excecao.getMessage();
    }
}
