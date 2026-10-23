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

// Resposta a um pedido sem token válido. O motivo detalhado vai para o log do
// servidor e o cliente recebe sempre o mesmo 401 genérico.

public class GenericAuthenticationEntryPoint implements AuthenticationEntryPoint {

    // Logger deste entry point.
    private static final Logger log = LoggerFactory.getLogger(GenericAuthenticationEntryPoint.class);

    // Chamado pelo Spring Security quando a autenticação falha.
    @Override
    public void commence(HttpServletRequest pedido, HttpServletResponse resposta,
            AuthenticationException excecao) throws IOException {

        // Regista no log o método, o caminho e a causa real da falha.
        log.warn("401 em {} {} -> {}", pedido.getMethod(), pedido.getRequestURI(),
                motivo(excecao));

        // Responde 401.
        resposta.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        // Header só com "Bearer": sem error nem error_description, que revelariam o motivo.
        resposta.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        // Declara o corpo como JSON.
        resposta.setContentType(MediaType.APPLICATION_JSON_VALUE);
        // Corpo genérico, igual para qualquer causa de falha.
        resposta.getWriter().write("{\"error\":\"unauthorized\"}");
    }

    // Produz a descrição da falha que vai para o log.
    private String motivo(AuthenticationException excecao) {
        // Erros de OAuth2 trazem um código e uma descrição próprios.
        if (excecao instanceof OAuth2AuthenticationException oauth) {
            // Erro padronizado que vem dentro da exceção.
            OAuth2Error erro = oauth.getError();
            // A descrição é opcional.
            String descricao = erro.getDescription();
            // Junta o código com a descrição, quando ela existe.
            return erro.getErrorCode() + (descricao != null ? ": " + descricao : "");
        }
        // Nas restantes exceções usa-se o nome da classe e a mensagem.
        return excecao.getClass().getSimpleName() + ": " + excecao.getMessage();
    }
}
