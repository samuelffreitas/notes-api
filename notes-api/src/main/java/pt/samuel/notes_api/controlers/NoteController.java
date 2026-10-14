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

@RestController
@RequestMapping("/notes")
public class NoteController {

    private final NoteService noteService;

    NoteController(NoteService noteService) {
        this.noteService = noteService;
    }

    @PreAuthorize("hasRole('app-user')")
    @PostMapping
    public ResponseEntity<NoteResponse> createNote(@Valid @RequestBody CreateNoteRequest pedido) {
        return ResponseEntity.status(HttpStatus.CREATED).body(noteService.create(pedido));
    }

    @PreAuthorize("hasRole('app-user')")
    @GetMapping
    public List<NoteResponse> listNotes() {
        return noteService.findAll();
    }

    @PreAuthorize("hasRole('app-user')")
    @GetMapping("/{id}")
    public ResponseEntity<NoteResponse> getNote(@PathVariable Long id) {
        return noteService.findById(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PreAuthorize("hasRole('app-user')")
    @PutMapping("/{id}")
    public ResponseEntity<NoteResponse> updateNote(@PathVariable Long id,
            @Valid @RequestBody CreateNoteRequest pedido) {
        return noteService.update(id, pedido)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PreAuthorize("hasRole('app-user')")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteNote(@PathVariable Long id) {
        return noteService.delete(id)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }
}
