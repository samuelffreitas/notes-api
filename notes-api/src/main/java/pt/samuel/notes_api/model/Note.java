package pt.samuel.notes_api.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.LocalDateTime;

// Entidade que mapeia a tabela note. É a única classe que o JPA persiste e
// nunca sai da camada de serviço.

// Declara a classe como entidade e aponta-lhe a tabela.
@Entity(name = "note")
@Table(name = "note")
public class Note {

    // Chave primária gerada pela própria base de dados.
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    // Título da nota.
    private String title;
    // Corpo da nota, guardado em TEXT para não ter limite de 255.
    @Column(columnDefinition = "TEXT")
    private String body;
    // Dono da nota: o sub do token de quem a criou.
    private String ownerId;
    // Equipa que define o âmbito de visibilidade da nota.
    private String teamId;
    // Momento da criação, preenchido antes do insert.
    private LocalDateTime createdAt;

    // Preenche o createdAt antes do insert, porque a coluna é NOT NULL e não
    // vem no corpo do pedido.
    @PrePersist
    protected void onCreate() {
        // Só preenche se ainda estiver vazio, para não sobrepor um valor dado.
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

    // Getters e setters usados pelo serviço para ler e preencher a nota.

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public String getOwnerId() {
        return ownerId;
    }

    public void setOwnerId(String ownerId) {
        this.ownerId = ownerId;
    }

    public String getTeamId() {
        return teamId;
    }

    public void setTeamId(String teamId) {
        this.teamId = teamId;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
