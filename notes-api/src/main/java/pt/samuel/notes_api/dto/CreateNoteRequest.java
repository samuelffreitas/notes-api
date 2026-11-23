package pt.samuel.notes_api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

// Corpo aceite num POST ou PUT de /notes. Só declara os campos que o cliente
// pode definir, por isso não há nada a filtrar depois.

public record CreateNoteRequest(

        // Título da nota, recusado em branco pela validação do pedido.
        @NotBlank(message = "o título é obrigatório")
        // A coluna é VARCHAR(255): sem este limite era o Postgres a recusar, já
        // dentro da transação, e a exceção saía como 500.
        @Size(max = 255, message = "o título é demasiado longo")
        // O Postgres não aceita 0x00 em nenhum tipo de texto. O @Pattern exige
        // correspondência total, por isso um nulo em qualquer posição reprova.
        @Pattern(regexp = "[^\\x00]*", message = "o título tem caracteres não permitidos")
        String title,

        // Corpo da nota, opcional.
        // Sem limite de tamanho por decisão: a coluna é TEXT. Mas o nulo é
        // recusado aqui também, senão o 500 continuava alcançável pelo corpo.
        @Pattern(regexp = "[^\\x00]*", message = "o corpo tem caracteres não permitidos")
        String body) {
}
