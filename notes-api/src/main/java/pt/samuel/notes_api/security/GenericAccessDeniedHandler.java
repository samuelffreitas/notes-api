package pt.samuel.notes_api.security;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// Resposta a um pedido autenticado mas sem permissão. Irmão do entry point: o
// motivo fica no log e o cliente recebe sempre o mesmo 403 genérico.

public class GenericAccessDeniedHandler implements AccessDeniedHandler {

    // Logger deste handler.
    private static final Logger log = LoggerFactory.getLogger(GenericAccessDeniedHandler.class);

    // Chamado quando o @PreAuthorize ou o serviço negam a operação.
    @Override
    public void handle(HttpServletRequest pedido, HttpServletResponse resposta,
            AccessDeniedException excecao) throws IOException {

        // Regista os 403 do @PreAuthorize, que de outra forma não deixavam rasto.
        log.warn("403 em {} {} -> {}", pedido.getMethod(), pedido.getRequestURI(),
                excecao.getMessage());

        // Responde 403.
        resposta.setStatus(HttpServletResponse.SC_FORBIDDEN);
        // Header só com "Bearer": o handler por omissão escreveria aqui o motivo.
        resposta.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        // Declara o corpo como JSON.
        resposta.setContentType(MediaType.APPLICATION_JSON_VALUE);
        // Corpo genérico, igual para qualquer recusa.
        resposta.getWriter().write("{\"error\":\"forbidden\"}");
    }
}
