package pt.samuel.notes_api.service;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
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
    // Vêm do token.

    private final NoteRepository noteRepository;

    NoteService(NoteRepository noteRepository) {
        this.noteRepository = noteRepository;
    }

    @Transactional
    public NoteResponse create(CreateNoteRequest pedido) {
        Note note = new Note();
        note.setTitle(pedido.title());
        note.setBody(pedido.body());
        Jwt token = tokenAutenticado();
        note.setOwnerId(token.getSubject());
        note.setTeamId(primeiraEquipa(token));
        return NoteResponse.from(noteRepository.save(note));
    }

    @Transactional(readOnly = true)
    public List<NoteResponse> findAll() {
        Jwt token = tokenAutenticado();
        String equipa = primeiraEquipa(token);

        List<Note> notas;
        if (temRole("app-admin")) {
            notas = noteRepository.findAll();
        } else if (temRole("app-team-lead")) {
            notas = noteRepository.findByTeamId(equipa);
        } else {
            notas = noteRepository.findByOwnerIdAndTeamId(token.getSubject(), equipa);
        }
        return notas.stream().map(NoteResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public Optional<NoteResponse> findById(Long id) {
        return noteRepository.findById(id).filter(this::podeAceder).map(NoteResponse::from);
    }

    /**
     * Atualiza os campos editáveis da nota. Devolve um Optional vazio se a nota
     * não existir, para o controller responder 404.
     */
    @Transactional
    public Optional<NoteResponse> update(Long id, CreateNoteRequest pedido) {
        return noteRepository.findById(id).filter(this::podeAceder).map(existente -> {
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
        Optional<Note> nota = noteRepository.findById(id).filter(this::podeAceder);
        if (nota.isEmpty()) {
            return false;
        }
        noteRepository.delete(nota.get());
        return true;
    }

    /**
     * Quem não tem acesso recebe 404, não 403: um 403 confirmaria que a nota
     * existe, e isso por si só já é informação sobre registos de outros.
     */
    private boolean podeAceder(Note note) {
        if (temRole("app-admin")) {
            return true;
        }
        Jwt token = tokenAutenticado();
        String equipa = primeiraEquipa(token);

        if (temRole("app-team-lead")) {
            return Objects.equals(note.getTeamId(), equipa);
        }
        return Objects.equals(note.getOwnerId(), token.getSubject())
                && Objects.equals(note.getTeamId(), equipa);
    }

    private boolean temRole(String role) {
        return SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(("ROLE_" + role)::equals);
    }

    // O token já foi validado pelo resource server; aqui só se lê.
    private Jwt tokenAutenticado() {
        return (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    // O mapper do Keycloak injeta uma lista; a coluna team_id guarda um valor.
    private String primeiraEquipa(Jwt token) {
        List<String> equipas = token.getClaimAsStringList("teams");
        return (equipas == null || equipas.isEmpty()) ? null : equipas.get(0);
    }
}
