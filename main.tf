terraform {
  required_providers {
    keycloak = {
      source  = "keycloak/keycloak"
      version = "~> 5.0"
    }
  }
}

variable "keycloak_admin_password" {
  type        = string
  description = "A password de administrador do Keycloak"
  sensitive   = true # Isto esconde a password nos logs do terminal
}

# Password comum às contas de teste do lab (joao, maria, pedro, ana).
# São contas descartáveis, sem valor fora deste ambiente local. Ainda assim
# a password não fica no código: define-a no terraform.tfvars (que não é versionado).
variable "test_users_password" {
  type        = string
  description = "Password inicial das contas de teste do realm notes-app"
  sensitive   = true
}

provider "keycloak" {
  client_id = "admin-cli"
  username  = "admin"
  password  = var.keycloak_admin_password
  url       = "http://localhost:8080"
}

resource "keycloak_realm" "notes-app" {
  realm   = "notes-app"
  enabled = true

  # 5m (o default do Keycloak) obriga a refazer o fluxo a cada 5 minutos
  # durante o desenvolvimento. 2h e so para o laboratorio.
  access_token_lifespan = "2h"
}

resource "keycloak_openid_client" "my_client" {
  realm_id                   = keycloak_realm.notes-app.id
  client_id                  = "notes-web"
  access_type                = "PUBLIC"
  pkce_code_challenge_method = "S256"
  valid_redirect_uris        = ["http://localhost:3000/callback"]
  standard_flow_enabled      = true

  # Trocar username+password por um token num so pedido contornaria o browser,
  # e com ele o PKCE. Fica desligado por decisao, nao por omissao do provider.
  direct_access_grants_enabled = false
}

# Resource server: representa a API. Não inicia nenhum fluxo, só recebe e
# valida tokens, por isso todos os fluxos ficam desligados.
resource "keycloak_openid_client" "notes_api" {
  realm_id                     = keycloak_realm.notes-app.id
  client_id                    = "notes-api"
  access_type                  = "CONFIDENTIAL"
  standard_flow_enabled        = false
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = false
}

# Acrescenta "notes-api" ao "aud" dos access tokens emitidos para o notes-web,
# para que a API possa confirmar que o token lhe é destinado.
resource "keycloak_openid_audience_protocol_mapper" "notes_web_audience_api" {
  realm_id  = keycloak_realm.notes-app.id
  client_id = keycloak_openid_client.my_client.id
  name      = "audience-notes-api"

  included_client_audience = keycloak_openid_client.notes_api.client_id

  add_to_access_token = true
  add_to_id_token     = false
}

resource "keycloak_role" "admin" {
  realm_id    = keycloak_realm.notes-app.id
  name        = "app-admin"
  description = "Administrador da Aplicação"

  # Role composta: quem a tem recebe também as outras duas no token.
  composite_roles = [
    keycloak_role.team-lead.id,
    keycloak_role.user.id,
  ]
}

resource "keycloak_role" "user" {
  realm_id    = keycloak_realm.notes-app.id
  name        = "app-user"
  description = "Utilizador da Aplicação"
}

resource "keycloak_role" "team-lead" {
  realm_id    = keycloak_realm.notes-app.id
  name        = "app-team-lead"
  description = "Líder de Equipa da Aplicação"

  # Role composta: um team-lead é sempre também um app-user.
  composite_roles = [
    keycloak_role.user.id,
  ]
}

resource "keycloak_group" "team_a" {
  realm_id = keycloak_realm.notes-app.id
  name     = "team-a"
}

resource "keycloak_group" "team_b" {
  realm_id = keycloak_realm.notes-app.id
  name     = "team-b"
}

resource "keycloak_user" "utilizadores" {
  for_each = {
    "user1" = { username = "joao.silva", first = "João", last = "Silva", email = "joao@empresa.com" }
    "user2" = { username = "maria.santos", first = "Maria", last = "Santos", email = "maria@empresa.com" }
    "user3" = { username = "pedro.gomes", first = "Pedro", last = "Gomes", email = "pedro@empresa.com" }
    "user4" = { username = "ana.pinto", first = "Ana", last = "Pinto", email = "ana@empresa.com" }
  }

  realm_id   = keycloak_realm.notes-app.id
  username   = each.value.username
  first_name = each.value.first
  last_name  = each.value.last
  email      = each.value.email
  enabled    = true

  initial_password {
    value     = var.test_users_password
    temporary = false
  }
}

resource "keycloak_user_groups" "membros_team_a" {
  for_each = toset(["user1", "user2"])

  realm_id  = keycloak_realm.notes-app.id
  user_id   = keycloak_user.utilizadores[each.key].id
  group_ids = [keycloak_group.team_a.id]
}

resource "keycloak_user_groups" "membros_team_b" {
  for_each = toset(["user3", "user4"])

  realm_id  = keycloak_realm.notes-app.id
  user_id   = keycloak_user.utilizadores[each.key].id
  group_ids = [keycloak_group.team_b.id]
}

# Atribuição de roles: só a role de topo de cada um. A hierarquia está
# declarada nas roles compostas acima, e o Keycloak expande-a no token.
locals {
  roles_por_utilizador = {
    "user1" = [keycloak_role.team-lead.id] # João  - lead team-a (traz app-user)
    "user2" = [keycloak_role.user.id]      # Maria - team-a
    "user3" = [keycloak_role.team-lead.id] # Pedro - lead team-b (traz app-user)
    "user4" = [keycloak_role.admin.id]     # Ana   - admin (traz as outras duas)
  }
}

resource "keycloak_user_roles" "roles_utilizadores" {
  for_each = local.roles_por_utilizador

  realm_id = keycloak_realm.notes-app.id
  user_id  = keycloak_user.utilizadores[each.key].id
  role_ids = each.value
}

resource "keycloak_openid_group_membership_protocol_mapper" "mapear_equipas_utilizador" {
  realm_id = keycloak_realm.notes-app.id

  client_id = keycloak_openid_client.my_client.id

  name = "mapper-equipas"

  claim_name = "teams"

  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true

  full_path = false
}
