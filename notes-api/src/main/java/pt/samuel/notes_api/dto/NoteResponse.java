package pt.samuel.notes_api.dto;

import java.time.LocalDateTime;

import pt.samuel.notes_api.model.Note;

// Nota devolvida pela API. Existe para a entidade Note nunca sair da camada de
// serviço: mudar o mapeamento JPA não muda o JSON.

public record NoteResponse(
        // Campos expostos na resposta, na ordem em que aparecem no JSON.
        Long id,
        String title,
        String body,
        String ownerId,
        String teamId,
        LocalDateTime createdAt) {

    // Copia a entidade para o DTO, campo a campo.
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
