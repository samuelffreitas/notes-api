package pt.samuel.notes_api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// Ponto de entrada da aplicação: é esta classe que o Spring Boot arranca e a
// partir do pacote dela que varre os componentes.

// Liga a configuração automática e a varredura de componentes deste pacote.
@SpringBootApplication
public class NotesApiApplication {

	public static void main(String[] args) {
		// Arranca o contexto do Spring e o servidor embutido.
		SpringApplication.run(NotesApiApplication.class, args);
	}

}
