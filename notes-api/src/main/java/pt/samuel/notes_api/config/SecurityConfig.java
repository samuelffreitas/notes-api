package pt.samuel.notes_api.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

import pt.samuel.notes_api.security.AudienceValidator;
import pt.samuel.notes_api.security.GenericAuthenticationEntryPoint;

// Código que  configura o Spring Security 
// para transformar a aplicação num Resource Server 

@Configuration
public class SecurityConfig {


    @Bean
    AuthenticationEntryPoint authenticationEntryPoint() {
        return new GenericAuthenticationEntryPoint();
    }

    // Monta o verificador de tokens.
    @Bean
    JwtDecoder jwtDecoder(OAuth2ResourceServerProperties propriedades,
            @Value("${notes.jwt.audience}") String audiencia) {

        // Lê o issuer-uri do application.yml.
        String issuer = propriedades.getJwt().getIssuerUri();

        // Cria o objeto que verifica tokens: vai ao Keycloak buscar as chaves
        // e sabe verificar assinaturas.
        NimbusJwtDecoder descodificador = JwtDecoders.fromIssuerLocation(issuer);

        // Junta num só objeto as verificações do Spring mais a tua.
        OAuth2TokenValidator<Jwt> validadores = new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuer),   // iss, exp, nbf
                new AudienceValidator(audiencia));               // aud  <- teu

        // Diz ao verificador: "além da assinatura, confere também estas claims."
        descodificador.setJwtValidator(validadores);

        return descodificador;
    }

    // Define as regras.
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationEntryPoint entryPoint)
            throws Exception {
        return http
                // não uses proteção CSRF
                .csrf(csrf -> csrf.disable())
                // não guardes sessão
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(pedidos -> pedidos
                        // /actuator/health é público
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        // tudo o resto exige token
                        .anyRequest().authenticated())
                // quando falhar, usa o meu GenericAuthenticationEntryPoint
                .exceptionHandling(e -> e.authenticationEntryPoint(entryPoint))
                .oauth2ResourceServer(oauth2 -> oauth2
                        // quando falhar, usa o meu GenericAuthenticationEntryPoint
                        .authenticationEntryPoint(entryPoint)
                        .jwt(jwt -> {
                        }))
                .build();
    }
}
