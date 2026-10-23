package pt.samuel.notes_api.controlers;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.security.access.prepost.PreAuthorize;

import jakarta.validation.Valid;
import pt.samuel.notes_api.dto.CreateNoteRequest;
import pt.samuel.notes_api.dto.NoteResponse;
import pt.samuel.notes_api.service.NoteService;

// Endpoints REST de /notes. Traduz pedidos HTTP em chamadas ao serviço e o
// resultado em códigos de resposta; não decide nada sobre acesso a registos.

// Expõe a classe como controller REST com todas as rotas sob /notes.
@RestController
@RequestMapping("/notes")
public class NoteController {

    // Serviço onde vivem as regras; o controller só lhe delega.
    private final NoteService noteService;

    // Injeção por construtor, feita pelo Spring.
    NoteController(NoteService noteService) {
        this.noteService = noteService;
    }

    // POST /notes, restrito a quem tem a role app-user.
    @PreAuthorize("hasRole('app-user')")
    @PostMapping
    public ResponseEntity<NoteResponse> createNote(@Valid @RequestBody CreateNoteRequest pedido) {
        // Cria a nota e devolve 201 com ela no corpo.
        return ResponseEntity.status(HttpStatus.CREATED).body(noteService.create(pedido));
    }

    // GET /notes, restrito a quem tem a role app-user.
    @PreAuthorize("hasRole('app-user')")
    @GetMapping
    public List<NoteResponse> listNotes() {
        // Devolve as notas que o serviço considera visíveis para quem pede.
        return noteService.findAll();
    }

    // GET /notes/{id}, restrito a quem tem a role app-user.
    @PreAuthorize("hasRole('app-user')")
    @GetMapping("/{id}")
    public ResponseEntity<NoteResponse> getNote(@PathVariable Long id) {
        // 200 com a nota, ou 404 se o serviço devolver vazio.
        return noteService.findById(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    // PUT /notes/{id}, restrito a quem tem a role app-user.
    @PreAuthorize("hasRole('app-user')")
    @PutMapping("/{id}")
    public ResponseEntity<NoteResponse> updateNote(@PathVariable Long id,
            @Valid @RequestBody CreateNoteRequest pedido) {
        // 200 com a nota atualizada, ou 404 se o serviço devolver vazio.
        return noteService.update(id, pedido)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    // DELETE /notes/{id}, restrito a quem tem a role app-user.
    @PreAuthorize("hasRole('app-user')")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteNote(@PathVariable Long id) {
        // 204 se apagou, 404 se a nota não existia ou não era visível.
        return noteService.delete(id)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }
}
