package pt.samuel.notes_api.security;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// Uma linha de log por pedido, com o que um incidente precisa para ser
// investigado: origem, método, rota, status, duração e quem fez o pedido.

public class RegistoDePedidosFilter extends OncePerRequestFilter {

    // Logger deste filtro.
    private static final Logger log = LoggerFactory.getLogger(RegistoDePedidosFilter.class);

    // Corre dentro da cadeia do Spring Security, depois da autenticação.
    @Override
    protected void doFilterInternal(HttpServletRequest pedido, HttpServletResponse resposta,
            FilterChain cadeia) throws ServletException, IOException {

        // Marca de partida, para medir quanto demorou a responder.
        long inicio = System.nanoTime();
        try {
            // Deixa o pedido seguir; a linha só se escreve quando ele volta.
            cadeia.doFilter(pedido, resposta);
        } finally {
            // No finally para a linha sair mesmo quando o pedido termina em exceção.
            long milissegundos = (System.nanoTime() - inicio) / 1_000_000;
            log.info("pedido: {} {} {} {}ms ip={} {}",
                    pedido.getMethod(), pedido.getRequestURI(), resposta.getStatus(),
                    milissegundos, origem(pedido), quemPediu());
        }
    }

    // Identidade de quem pediu, lida do token já validado.
    private String quemPediu() {
        // O contexto ainda está preenchido: quem o limpa corre mais acima na cadeia.
        Authentication autenticacao = SecurityContextHolder.getContext().getAuthentication();
        // Pedido sem token válido não tem identidade para registar.
        if (autenticacao == null || !(autenticacao.getPrincipal() instanceof Jwt token)) {
            return "azp=- sub=-";
        }
        // O azp é a única identificação útil de um serviço; o sub, a de uma pessoa.
        return "azp=" + token.getClaimAsString("azp") + " sub=" + token.getSubject();
    }

    // Endereço de quem abriu a ligação TCP.
    static String origem(HttpServletRequest pedido) {
        // De propósito não se lê o X-Forwarded-For: esse cabeçalho é posto pelo
        // cliente, e registá-lo seria deixar o atacante escolher o que fica no log.
        // Atrás de um proxy, é o proxy que tem de ser configurado como de confiança.
        return pedido.getRemoteAddr();
    }
}
