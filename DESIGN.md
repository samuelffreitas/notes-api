**Aplicação:**

- Sistema de gestão e criação de notas
- Utilizadores organizadores equipa e consequentemente administrados por um administrador
- Cada nota tem dono (owner_id) e âmbito de equipa (team_id)

**Papéis:**

| Papel | O que pode fazer |
|---|---|
| `app-user` | criar, ler, editar e apagar as suas próprias notas |
| `app-team-lead` | o mesmo, mais ler as notas da sua equipa |
| `app-admin` | ler e apagar qualquer nota |

O prefixo `app-` distingue as roles desta aplicação das roles que o Keycloak
cria por defeito em cada realm (`offline_access`, `uma_authorization`, `default-roles-*`).

**Notas práticas:**

1. Um `app-team-lead` da equipa A não pode ver uma nota da equipa B, porque
o acesso à informação não é determinado pelo cargo ou hierarquia, mas sim pelo contexto da utilização
da mesma. Como a nota pertence à equipa B, o líder da equipa A não precisa dela para realizar o seu trabalho.
( Need to Know e segregação de dados)

2. Se alguém muda da equipa A para a B, o elemento perde acesso a notas da equipa anterior que escreveu :
- A verificação de propriedade deixa de chegar sozinha, isto é, as querys terão que decidir pelo ownerId e
a equipa atual
- A lista "as minhas notas" irá automaticamente encolher
- O acesso é calculado a partir da equipa atual, não concedido e guardado, o que faz com que
quando alguém mude de equipa, o acesso antigo desaparece sozinho.
- Nota: escolhi o ambito (ela já não pertence à equipa A.) á propriedade (ela vê).

3. O RBAC puro deixa de chegar quando falha ao tentar controlar o acesso a registos específicos e 
quando o numero de roles ultrapassa o numero de colaboradores da empresa (role explosion ).

4. Os utilizadores não vivem na  base de dados, vivem no Keycloak. 
O owner_id guarda o sub do token.