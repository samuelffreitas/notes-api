package pt.samuel.notes_api.Repository;

import org.springframework.data.jpa.repository.JpaRepository;

import pt.samuel.notes_api.model.Note;

public interface NoteRepository extends JpaRepository<Note, Long> {

}
