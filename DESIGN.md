# Design

## The application

- A notes creation and management system.
- Users are organized by team and, consequently, administered by an administrator.
- Every note has an owner (owner_id) and a team scope (team_id).

## Roles

| Role | What it can do |
|---|---|
| app-user | create, read, edit and delete their own notes |
| app-team-lead | the same, plus reading their team's notes |
| app-admin | read and delete any note |

The app- prefix distinguishes this application's roles from the ones Keycloak
creates by default in every realm (offline_access, uma_authorization,
default-roles-*).

## Design notes

### 1. Access follows context, not rank

An app-team-lead of team A cannot see a note belonging to team B. Access to
information is not determined by position or hierarchy, but by the context in
which that information is used. The note belongs to team B, so team A's lead
does not need it to do their job.

*(Need to Know and data segregation.)*

### 2. Changing team removes access to what was left behind

If someone moves from team A to team B, they lose access to the notes they
wrote in the previous team.

- An ownership check is no longer enough on its own: the queries have to decide
  on the ownerId **and** the current team.
- Access is computed from the current team, not granted and stored — so when
  someone changes team, the old access disappears by itself.

Note: I chose scope (she no longer belongs to team A) over ownership (she gets
to see it).

### 3. RBAC alone does not reach far enough

Pure RBAC answers *"may this person use this operation?"* and not *"over this
record?"*. That is why the per-record check lives in the service, and not only
in @PreAuthorize.

### 4. Users do not live in the database

They live in Keycloak. owner_id stores the token's sub.

## Deferred decisions

1. **Consistency as an application rule** — an endpoint that returns 403 where
   the others return 404 is an oracle in itself. The rule has to live in a
   single place, not in every controller.
2. **Centralized authorization** — the decision lives today in a private method
   of the service. With three entities it is repeated three times, and diverges.
