# Notes-api

An OAuth 2.0 resource server exposing a notes REST API, with token validation
and three-layer authorization against Keycloak.

## The purpose

This application was built in an IAM (Identity and Access Management) context to explore the strict separation of responsibilities between an Authorization Server (Keycloak) and a Resource Server (this API). Under this model, the API does not manage users, passwords or credentials, focusing instead on storing its own resources (the notes). The identity of each record's owner is established through the sub claim in the JWT, which forces the Resource Server to accept an externally signed token and make secure access decisions about claims it neither produced nor controls.

The project's central goal is to show that security in an API goes far beyond simply validating the token, serving as a demonstration that a valid token is not synonymous with authorization. To prove it, the application implements access control structured in three distinct layers:

1. Authentication: Validation of the JWT against Keycloak's JWKS endpoint (signature, iss, exp, nbf and aud), with no dependency on the local database.

2. RBAC model: Extraction of roles from the realm_access.roles claim, converted into authorities that protect the endpoints at runtime.

3. Authorization: The layer that mitigates IDOR vulnerabilities. It dynamically validates access to each note by cross-checking the resource ID against the sub claim and the team in the token.

## The model

Access control rests on three roles declared in Keycloak, two of them
composite: app-admin inherits app-team-lead, which inherits app-user.

- app-user -> Create, read, edit and delete their own notes.
- app-team-lead -> Same permissions as a user, plus reading their team's notes.
- app-admin -> Read and delete any note in the system.

Every note has an owner (owner_id / the token's sub) within a team context (team_id / the teams claim). Under the Need to Know principle, context prevails over ownership: if a user moves from team A to team B, they immediately lose access to the notes they wrote in team A.

To mitigate information disclosure, the API's responses are defensive. HTTP 404 Not Found is returned when the resource falls outside the user's visibility context, making it impossible to tell a restricted ID from one that does not exist. HTTP 403 Forbidden is reserved strictly for cases where the resource's existence is already known but the intended operation violates the authorization rules.

## Architecture

```
  browser / Postman
        │  1. login (authorization code + PKCE)
        ▼
  ┌──────────────┐                        ┌──────────────────┐
  │   Keycloak   │◄── realm, clients, ────│    Terraform     │
  │   :8080      │    roles, users,       │    (main.tf)     │
  │              │    mappers             └──────────────────┘
  │ authorization│
  │    server    │
  └──────┬───────┘
         │  2. access token (JWT)
         ▼
  ┌──────────────┐   3. verifies the signature
  │  notes-api   │──────► realm JWKS ─────────┐
  │   :8090      │◄──────────────────────────-┘
  │              │
  │  resource    │   4. authorizes by owner/team/role
  │   server     │
  └──────┬───────┘
         │  5. SQL
         ▼
  ┌──────────────┐
  │  PostgreSQL  │
  │   :5433      │
  └──────────────┘
```

Following the Zero Trust principle, the API and Keycloak operate in isolation: that is,
Keycloak never contacts the API, and the API does not contact it on every request. It
verifies signatures in memory, with the JWKS public keys that it fetches at startup,
keeps in cache and fetches again when Keycloak rotates the keys.
As a matter of good practice, all of Keycloak's infrastructure is declared and managed through Terraform, in main.tf.

## Running it

**Requirements:** Docker, Terraform, Java 21. Ports **8080**, **5433** and
**8090** must be free.

### 1. Infrastructure

```bash
docker compose up -d
```

Starts Keycloak (:8080), its own database and the notes Postgres (:5433).

Copy .env.example and fill in the three passwords. The one for the notes Postgres is NOTES_DB_PASSWORD.

### 2. Configure the realm

```bash
terraform init      # first time only
terraform apply
```

Creates in Keycloak the notes-app realm, the two clients, the roles, the teams and the
four test users.

Copy terraform.tfvars.example. keycloak_admin_password must be the same as KEYCLOAK_ADMIN_PASSWORD in .env — it is the same account, used in two places.

### 3. The application

```bash
cd notes-api
./mvnw spring-boot:run
```

- Check whether the application has started:

```bash
curl http://localhost:8090/actuator/health    # the only public endpoint
```

### 4. Get a token

The notes-web client uses *authorization code* with PKCE and redirects to
http://localhost:3000/callback. The *direct access grant* is deliberately
disabled, so there is no shortcut through curl: the token is obtained through
the flow, by hand.

Test users, all with the same password (test_users_password):

| User | Team | Assigned role |
|---|---|---|
| maria.santos | team-a | app-user |
| joao.silva | team-a | app-team-lead |
| pedro.gomes | team-b | app-team-lead |
| ana.pinto | team-b | app-admin |

With the token:

```bash
curl http://localhost:8090/notes -H "Authorization: Bearer $TOKEN"
curl http://localhost:8090/me    -H "Authorization: Bearer $TOKEN"
```

/me shows the sub, the team, the token's roles and the authorities that resulted
from them.

## Testing

Testing was done manually, running in Postman a matrix of requests with tokens from different users against the same notes, covering the combinations of owner, team and
role, and confirming the response code of each one, including that a 404
caused by lack of visibility is indistinguishable from a 404 caused by non-existence, on the user's side.

## Deliberately not done

- **No frontend.** Tokens are obtained by hand and requests are made with curl
  or Postman. What the project demonstrates lives on the server side.
- **No TLS.** Everything over local HTTP, and only because this is a lab.
- **Authorization policy in code.** The rules live in private methods of the
  service. With more than one entity, this would call for a policy layer or
  query-level filters.
- **No deprovisioning.** owner_id stores the token's sub and there is no
  foreign key to Keycloak — nor could there be, they are separate databases.
  If a user is deleted in the IdP, their notes stay in the
  table, visible to app-admin and to the team's team-lead, and deletable only by app-admin. Nobody inherits them and nothing signals that the owner has gone.
