"""Regras globais da suite de seguranca.

Duas regras valem para TODAS as respostas, em todos os cenarios:
  1. um HTTP 500 faz o teste falhar de imediato;
  2. o corpo da resposta nunca pode conter stack traces, SQL, caminhos do
     sistema, nomes internos nem valores de segredos.

Quem fala com a API fala por aqui, nunca por requests.* diretamente.
"""

import os
import re

import requests

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8090").rstrip("/")
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
REALM = os.environ.get("KEYCLOAK_REALM", "notes-app")
TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "10"))


class Falha500(AssertionError):
    """HTTP 500: a regra diz que o teste falha de imediato."""


class FugaNoCorpo(AssertionError):
    """O corpo da resposta expoe informacao que nao devia sair do servidor."""


# (nome legivel, expressao). O nome e o que aparece no relatorio: o valor que
# bateu nunca e impresso, para o relatorio nao se tornar ele proprio a fuga.
PADROES_PROIBIDOS = [
    ("stack trace java",      re.compile(r"\bat (?:org|java|jakarta|com|pt)\.[\w.$]+\(")),
    ("excecao java",          re.compile(r"\b[A-Z]\w*Exception\b")),
    ("causa encadeada",       re.compile(r"Caused by:")),
    ("traceback python",      re.compile(r"Traceback \(most recent call last\)")),
    ("hibernate",             re.compile(r"org\.hibernate")),
    ("driver do postgres",    re.compile(r"org\.postgresql")),
    ("spring interno",        re.compile(r"org\.springframework")),
    ("pacote do projeto",     re.compile(r"pt\.samuel\.notes_api")),
    ("url jdbc",              re.compile(r"jdbc:postgresql")),
    ("tabela do flyway",      re.compile(r"flyway_schema_history")),
    ("ficheiro e linha java", re.compile(r"\.java:\d+")),
    ("caminho do sistema",    re.compile(r"/home/[a-z]")),
    ("pagina de erro spring", re.compile(r"Whitelabel Error Page")),
    ("sql cru",               re.compile(r"(?i)\binsert\s+into\b|\bdelete\s+from\b|"
                                         r"\bselect\b[^\n]{0,80}\bfrom\b")),
]

# Valores que nunca podem aparecer numa resposta. Preenchido pelo mint_tokens.sh
# com os segredos reais, para o varrimento procurar os segredos e nao so padroes.
VALORES_PROIBIDOS = [v for v in os.environ.get("VALORES_PROIBIDOS", "").split("\x1f") if v]


def procurar_fugas(corpo, enviado=None):
    """Problemas encontrados no corpo. 'enviado' evita acusar o nosso proprio eco."""
    if not corpo:
        return []
    problemas = []
    for nome, expressao in PADROES_PROIBIDOS:
        achado = expressao.search(corpo)
        if not achado:
            continue
        # Se o que bateu foi um payload que nos proprios mandamos e a API
        # devolveu de volta, isso e eco e nao fuga do servidor.
        if enviado and achado.group(0) in enviado:
            continue
        problemas.append(nome)
    for i, valor in enumerate(VALORES_PROIBIDOS):
        if len(valor) >= 8 and valor in corpo:
            problemas.append("valor de segredo #%d" % (i + 1))
    return problemas


def pedir(metodo, caminho, token=None, corpo=None, cabecalhos=None, base=None):
    """Um pedido a API com as duas regras globais aplicadas a resposta."""
    url = (base or BASE_URL) + caminho
    hdrs = {}
    if token:
        hdrs["Authorization"] = "Bearer " + token
    if corpo is not None:
        hdrs["Content-Type"] = "application/json"
    if cabecalhos:
        hdrs.update(cabecalhos)

    resposta = requests.request(metodo, url, headers=hdrs, data=corpo,
                                timeout=TIMEOUT, allow_redirects=False)

    if resposta.status_code == 500:
        raise Falha500(
            "500 em %s %s -- a regra da suite diz que isto falha de imediato. "
            "Primeiros 200 caracteres do corpo: %r"
            % (metodo, caminho, resposta.text[:200]))

    problemas = procurar_fugas(resposta.text, enviado=corpo)
    if problemas:
        raise FugaNoCorpo(
            "%s %s (HTTP %d) expoe: %s"
            % (metodo, caminho, resposta.status_code, ", ".join(sorted(set(problemas)))))

    return resposta


def token_de_servico(client_id, client_secret):
    """Um access token por client_credentials, sem utilizador nenhum."""
    r = requests.post(
        "%s/realms/%s/protocol/openid-connect/token" % (KEYCLOAK_URL, REALM),
        data={"grant_type": "client_credentials",
              "client_id": client_id,
              "client_secret": client_secret},
        timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()["access_token"]
