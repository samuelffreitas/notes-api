package pt.samuel.notes_api.service;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import pt.samuel.notes_api.Repository.NoteRepository;
import pt.samuel.notes_api.dto.CreateNoteRequest;
import pt.samuel.notes_api.dto.NoteResponse;
import pt.samuel.notes_api.model.Note;

// Regras de negócio e de autorização das notas, e conversão entre DTO e
// entidade. Não conhece HTTP: devolve DTOs, Optional e boolean.

// Declara a classe como bean de serviço do Spring.
@Service
public class NoteService {

    // Logger onde ficam os 403 e os 404 com o respetivo motivo.
    private static final Logger log = LoggerFactory.getLogger(NoteService.class);

    // Repositório que faz as queries à tabela note.
    private final NoteRepository noteRepository;

    // Injeção por construtor, feita pelo Spring.
    NoteService(NoteRepository noteRepository) {
        this.noteRepository = noteRepository;
    }

    // Cria uma nota cujo dono e equipa vêm do token.
    @Transactional
    public NoteResponse create(CreateNoteRequest pedido) {
        // Token de quem faz o pedido, já validado pelo resource server.
        Jwt token = tokenAutenticado();

        // Equipa de quem pede, que passa a ser o âmbito da nota.
        String equipa = primeiraEquipa(token);
        // Sem equipa não há âmbito, e team_id é NOT NULL: recusa-se em vez de rebentar.
        if (equipa == null) {
            log.warn("403 criar recusado a sub={}: token sem equipa", token.getSubject());
            throw new AccessDeniedException("operacao nao permitida");
        }

        // Entidade nova, ainda sem id nem createdAt.
        Note note = new Note();
        // Título e corpo são os únicos campos que o cliente define.
        note.setTitle(pedido.title());
        note.setBody(pedido.body());
        // Dono e equipa vêm do token: vindos do pedido seriam mass assignment.
        note.setOwnerId(token.getSubject());
        note.setTeamId(equipa);
        // Grava e devolve a nota já com id e createdAt.
        return NoteResponse.from(noteRepository.save(note));
    }

    // Lista as notas visíveis para quem pede, filtrando já na query.
    @Transactional(readOnly = true)
    public List<NoteResponse> findAll() {
        // Token de quem faz o pedido.
        Jwt token = tokenAutenticado();
        // Equipa de quem faz o pedido.
        String equipa = primeiraEquipa(token);

        // Notas a devolver, escolhidas conforme a role.
        List<Note> notas;
        if (temRole("app-admin")) {
            // O admin vê todas as notas do sistema.
            notas = noteRepository.findAll();
        } else if (temRole("app-team-lead")) {
            // O team-lead vê as notas da sua equipa.
            notas = noteRepository.findByTeamId(equipa);
        } else {
            // Os restantes vêem só as suas, dentro da sua equipa.
            notas = noteRepository.findByOwnerIdAndTeamId(token.getSubject(), equipa);
        }
        // Converte cada entidade no DTO de resposta.
        return notas.stream().map(NoteResponse::from).toList();
    }

    // Devolve uma nota pelo id, se existir e for visível.
    @Transactional(readOnly = true)
    public Optional<NoteResponse> findById(Long id) {
        // Converte no DTO só quando a nota passa a verificação de visibilidade.
        return visivel(id).map(NoteResponse::from);
    }

    // Atualiza os campos editáveis de uma nota.
    @Transactional
    public Optional<NoteResponse> update(Long id, CreateNoteRequest pedido) {
        // Vazio se a nota não existir ou não for visível, o que dá 404.
        return visivel(id).map(existente -> {
            // Poder ver não basta: editar exige ser o dono.
            exigir(podeEditar(existente), id, "editar");
            // Só o título e o corpo mudam; id, createdAt, ownerId e teamId ficam.
            existente.setTitle(pedido.title());
            existente.setBody(pedido.body());
            // Grava e devolve a nota atualizada.
            return NoteResponse.from(noteRepository.save(existente));
        });
    }

    // Apaga uma nota; devolve false se ela não existir ou não for visível.
    @Transactional
    public boolean delete(Long id) {
        // Carrega a nota só se for visível para quem pede.
        Optional<Note> nota = visivel(id);
        // Nada a apagar, e o controller traduz isto em 404.
        if (nota.isEmpty()) {
            return false;
        }
        // Apagar exige ser o dono ou ter a role app-admin.
        exigir(podeApagar(nota.get()), id, "apagar");
        // Remove a linha da tabela.
        noteRepository.delete(nota.get());
        // Sinaliza ao controller que apagou, para um 204.
        return true;
    }

    // Carrega a nota se existir e for visível; nos dois casos de vazio dá 404.
    private Optional<Note> visivel(Long id) {
        // Procura a nota pelo id, sem olhar ainda a quem pertence.
        Optional<Note> nota = noteRepository.findById(id);
        // Não existe: fica no log e devolve-se vazio.
        if (nota.isEmpty()) {
            log.warn("404 nota {} nao existe (pedida por sub={})", id, tokenAutenticado().getSubject());
            return Optional.empty();
        }
        // Existe mas não é visível: também vazio, para o cliente não distinguir os casos.
        if (!podeVer(nota.get())) {
            log.warn("404 nota {} existe mas nao e visivel para sub={} (dono={}, equipa da nota={})",
                    id, tokenAutenticado().getSubject(), nota.get().getOwnerId(), nota.get().getTeamId());
            return Optional.empty();
        }
        // Visível: segue para quem a pediu.
        return nota;
    }

    // Nega a operação quando a nota é visível mas a ação não é permitida.
    private void exigir(boolean permitido, Long id, String operacao) {
        // 403 e não 404: quem chega aqui já sabe que a nota existe.
        if (!permitido) {
            log.warn("403 {} na nota {} recusado a sub={}", operacao, id, tokenAutenticado().getSubject());
            throw new AccessDeniedException("operacao nao permitida");
        }
    }

    // Quem pode ler: o admin tudo, o team-lead a sua equipa, os outros as suas.
    private boolean podeVer(Note note) {
        // O admin vê qualquer nota do sistema.
        if (temRole("app-admin")) {
            return true;
        }
        // O team-lead vê as notas da equipa a que pertence.
        if (temRole("app-team-lead") && Objects.equals(note.getTeamId(), equipaAtual())) {
            return true;
        }
        // Os restantes vêem só as suas.
        return ehDono(note);
    }

    // Editar é exclusivo do dono: nem o team-lead nem o admin editam notas alheias.
    private boolean podeEditar(Note note) {
        return ehDono(note);
    }

    // Apagar é do dono ou do admin.
    private boolean podeApagar(Note note) {
        return temRole("app-admin") || ehDono(note);
    }

    // Dono é quem tem o mesmo sub e continua na equipa da nota.
    private boolean ehDono(Note note) {
        // A equipa conta sempre: mudar de equipa faz perder as notas lá deixadas.
        return Objects.equals(note.getOwnerId(), tokenAutenticado().getSubject())
                && Objects.equals(note.getTeamId(), equipaAtual());
    }

    // Equipa de quem faz o pedido atual.
    private String equipaAtual() {
        return primeiraEquipa(tokenAutenticado());
    }

    // Verifica se quem pede tem uma role, pela authority ROLE_ correspondente.
    private boolean temRole(String role) {
        return SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(("ROLE_" + role)::equals);
    }

    // Token do pedido atual, que o resource server já validou.
    private Jwt tokenAutenticado() {
        return (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    // Primeira equipa da claim teams, ou null se o token não trouxer nenhuma.
    private String primeiraEquipa(Jwt token) {
        // O mapper do Keycloak injeta uma lista; a coluna team_id guarda um valor.
        List<String> equipas = token.getClaimAsStringList("teams");
        return (equipas == null || equipas.isEmpty()) ? null : equipas.get(0);
    }
}
