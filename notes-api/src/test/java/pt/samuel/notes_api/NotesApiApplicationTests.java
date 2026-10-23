package pt.samuel.notes_api;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

// Único teste do projeto: verifica que o contexto do Spring arranca. Exige o
// Keycloak a correr, porque o bean do JwtDecoder faz descoberta OIDC.

// Arranca a aplicação inteira num contexto de teste.
@SpringBootTest
class NotesApiApplicationTests {

	// Falha se algum bean não se conseguir construir.
	@Test
	void contextLoads() {
	}

}
