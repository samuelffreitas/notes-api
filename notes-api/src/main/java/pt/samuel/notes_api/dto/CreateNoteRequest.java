package pt.samuel.notes_api.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Corpo aceite num POST/PUT de /notes.
 *
 * Só tem title e body de propósito: o id é atribuído pela base de dados, o
 * createdAt pela entidade, e o ownerId/teamId pelo serviço. Campos que o
 * cliente não pode definir não existem aqui, logo não há nada a filtrar.
 */
public record CreateNoteRequest(

        @NotBlank(message = "o título é obrigatório") String title,

        String body) {
}
