package pt.samuel.notes_api.dto;

import java.time.LocalDateTime;

import pt.samuel.notes_api.model.Note;

/**
 * Representação de uma nota devolvida pela API. A entidade Note nunca sai da
 * camada de serviço, por isso alterações ao mapeamento JPA não mudam o JSON.
 */
public record NoteResponse(
        Long id,
        String title,
        String body,
        String ownerId,
        String teamId,
        LocalDateTime createdAt) {

    public static NoteResponse from(Note note) {
        return new NoteResponse(
                note.getId(),
                note.getTitle(),
                note.getBody(),
                note.getOwnerId(),
                note.getTeamId(),
                note.getCreatedAt());
    }
}
