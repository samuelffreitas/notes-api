#!/usr/bin/env bash
# Preenche as variaveis de ambiente que a suite consome.
#
#   ./mint_tokens.sh [ficheiro-de-saida]
#   set -a; . <ficheiro-de-saida>; set +a
#   python3 -m unittest discover -v
#
# Escreve os tokens e os segredos num ficheiro FORA do repositorio; o caminho
# por omissao fica em /tmp. Nada disto pode ser versionado.
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAIDA="${1:-/tmp/notes-api-seguranca.env}"
KC="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${KEYCLOAK_REALM:-notes-app}"
TOKEN_URL="$KC/realms/$REALM/protocol/openid-connect/token"

cd "$RAIZ"

servico() { # client_id client_secret
  curl -sf -X POST "$TOKEN_URL" -d grant_type=client_credentials \
    -d "client_id=$1" --data-urlencode "client_secret=$2" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}

humano() { # username password
  curl -sf -X POST "$TOKEN_URL" -d grant_type=password -d client_id=notes-web \
    -d scope=openid -d "username=$1" --data-urlencode "password=$2" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' 2>/dev/null \
    || echo ""
}

SEGREDO_A="$(terraform output -raw notes_exporter_secret)"
SEGREDO_B="$(terraform output -raw notes_reporter_secret)"
PW_UTILIZADORES="$(grep -oP 'test_users_password[[:space:]]*=[[:space:]]*"\K[^"]+' terraform.tfvars)"

A="$(servico notes-exporter "$SEGREDO_A")"
B="$(servico notes-reporter "$SEGREDO_B")"
ADMIN="$(humano ana.pinto "$PW_UTILIZADORES")"
LEAD="$(humano joao.silva "$PW_UTILIZADORES")"

# O token expirado tem de ser genuinamente assinado pelo Keycloak, por isso
# e minado e guardado; fica valido durante o access_token_lifespan do cliente
# (300s) e so depois disso serve para o teste. O ficheiro e reaproveitado
# entre corridas: uma vez velho, serve sempre.
CACHE="${SAIDA%.env}.expirado"
if [ ! -f "$CACHE" ] || python3 - "$CACHE" <<'PY'
import base64, json, sys, time
try:
    t = open(sys.argv[1]).read().strip()
    c = json.loads(base64.urlsafe_b64decode((lambda p: p + "=" * (-len(p) % 4))(t.split(".")[1])))
    # sai 0 (= precisa de novo) so se o que esta em cache nem expirado esta
    # nem vai expirar em menos de uma hora
    sys.exit(0 if c["exp"] > time.time() + 3600 else 1)
except Exception:
    sys.exit(0)
PY
then
  servico notes-exporter "$SEGREDO_A" > "$CACHE"
  echo "token para expirar: minado agora, pronto dentro de 300s" >&2
fi
EXPIRADO="$(cat "$CACHE")"

# Os segredos reais, para o varrimento de fugas os procurar nas respostas.
# Separados por 0x1f, que nao aparece em nenhum deles.
mapfile -t VALORES < <(
  printf '%s\n' "$SEGREDO_A" "$SEGREDO_B" "$PW_UTILIZADORES"
  grep -oP 'keycloak_admin_password[[:space:]]*=[[:space:]]*"\K[^"]+' terraform.tfvars
  grep -oP '^NOTES_DB_PASSWORD=\K.*' .env
  grep -oP '^KEYCLOAK_DB_PASSWORD=\K.*' .env
)
PROIBIDOS="$(printf '%s\x1f' "${VALORES[@]}")"

umask 077
{
  echo "BASE_URL=${BASE_URL:-http://localhost:8090}"
  echo "KEYCLOAK_URL=$KC"
  echo "KEYCLOAK_REALM=$REALM"
  echo "APP_LOG=${APP_LOG:-}"
  echo "PW_UTILIZADORES=$PW_UTILIZADORES"
  echo "TOKEN_SERVICO_A=$A"
  echo "TOKEN_SERVICO_B=$B"
  echo "TOKEN_EXPIRADO=$EXPIRADO"
  echo "TOKEN_HUMANO_ADMIN=$ADMIN"
  echo "TOKEN_HUMANO_LEAD=$LEAD"
  echo "VALORES_PROIBIDOS=$PROIBIDOS"
} > "$SAIDA"

{
  echo "escrito em $SAIDA"
  printf '  %-22s %s\n' \
    TOKEN_SERVICO_A      "$([ -n "$A" ] && echo ok || echo FALTA)" \
    TOKEN_SERVICO_B      "$([ -n "$B" ] && echo ok || echo FALTA)" \
    TOKEN_HUMANO_ADMIN   "$([ -n "$ADMIN" ] && echo ok || echo 'FALTA (direct access grants desligado?)')" \
    TOKEN_HUMANO_LEAD    "$([ -n "$LEAD" ] && echo ok || echo 'FALTA (direct access grants desligado?)')" \
    TOKEN_EXPIRADO       "$([ -n "$EXPIRADO" ] && echo ok || echo FALTA)" \
    VALORES_PROIBIDOS    "${#VALORES[@]} valores"
} >&2
