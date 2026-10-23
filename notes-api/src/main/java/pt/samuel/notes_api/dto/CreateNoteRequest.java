package pt.samuel.notes_api.dto;

import jakarta.validation.constraints.NotBlank;

// Corpo aceite num POST ou PUT de /notes. Só declara os campos que o cliente
// pode definir, por isso não há nada a filtrar depois.

public record CreateNoteRequest(

        // Título da nota, recusado em branco pela validação do pedido.
        @NotBlank(message = "o título é obrigatório") String title,

        // Corpo da nota, opcional.
        String body) {
}
