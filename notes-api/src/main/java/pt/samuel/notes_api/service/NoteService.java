package pt.samuel.notes_api.service;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import pt.samuel.notes_api.Repository.NoteRepository;
import pt.samuel.notes_api.dto.CreateNoteRequest;
import pt.samuel.notes_api.dto.NoteResponse;
import pt.samuel.notes_api.model.Note;

/**
 * Regras de negócio das notas e conversão entre DTO e entidade.
 *
 * Não conhece HTTP: devolve DTOs e Optional/boolean, e é o controller que
 * traduz isso em status codes.
 */
@Service
public class NoteService {

    // O ownerId e o teamId não vêm do pedido: seriam mass assignment, porque
    // deixariam o cliente escolher a quem pertence a nota e que equipa a vê.
    // TODO: replace with values from the authenticated JWT (Day 3)
    private static final String OWNER_ID_PLACEHOLDER = "owner-placeholder";
    private static final String TEAM_ID_PLACEHOLDER = "team-placeholder";

    private final NoteRepository noteRepository;

    NoteService(NoteRepository noteRepository) {
        this.noteRepository = noteRepository;
    }

    @Transactional
    public NoteResponse create(CreateNoteRequest pedido) {
        Note note = new Note();
        note.setTitle(pedido.title());
        note.setBody(pedido.body());
        // TODO: replace with values from the authenticated JWT (Day 3)
        note.setOwnerId(OWNER_ID_PLACEHOLDER);
        note.setTeamId(TEAM_ID_PLACEHOLDER);
        return NoteResponse.from(noteRepository.save(note));
    }

    @Transactional(readOnly = true)
    public List<NoteResponse> findAll() {
        return noteRepository.findAll().stream().map(NoteResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public Optional<NoteResponse> findById(Long id) {
        return noteRepository.findById(id).map(NoteResponse::from);
    }

    /**
     * Atualiza os campos editáveis da nota. Devolve um Optional vazio se a nota
     * não existir, para o controller responder 404.
     */
    @Transactional
    public Optional<NoteResponse> update(Long id, CreateNoteRequest pedido) {
        return noteRepository.findById(id).map(existente -> {
            // Só o title e o body são editáveis. O id e o createdAt mantêm-se
            // porque se atualiza a entidade carregada, e o ownerId/teamId
            // ficam como estavam: não são do cliente para mudar.
            existente.setTitle(pedido.title());
            existente.setBody(pedido.body());
            return NoteResponse.from(noteRepository.save(existente));
        });
    }

    /**
     * @return false se a nota não existir, para o controller responder 404.
     */
    @Transactional
    public boolean delete(Long id) {
        if (!noteRepository.existsById(id)) {
            return false;
        }
        noteRepository.deleteById(id);
        return true;
    }
}
