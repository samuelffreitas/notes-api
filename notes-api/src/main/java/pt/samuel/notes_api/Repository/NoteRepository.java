package pt.samuel.notes_api.Repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import pt.samuel.notes_api.model.Note;

public interface NoteRepository extends JpaRepository<Note, Long> {

    // Usadas pela listagem: filtra-se na query em vez de carregar tudo e
    // descartar em memória.
    List<Note> findByTeamId(String teamId);

    List<Note> findByOwnerIdAndTeamId(String ownerId, String teamId);
}
