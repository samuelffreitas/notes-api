package pt.samuel.notes_api.Repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import pt.samuel.notes_api.model.Note;

// Acesso à tabela note. O Spring Data gera a implementação e traduz o nome de
// cada método na query SQL correspondente.

public interface NoteRepository extends JpaRepository<Note, Long> {

    // Todas as notas de uma equipa, para a listagem do team-lead.
    List<Note> findByTeamId(String teamId);

    // As notas de um dono na sua equipa: filtra-se na query, não em memória.
    List<Note> findByOwnerIdAndTeamId(String ownerId, String teamId);
}
