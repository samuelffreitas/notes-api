"""Suite adversarial do notes-api.

Camada 2: nao prova que o servico faz o que foi desenhado (isso e a camada 1,
os testes de aceitacao do commit 00345bf) -- ataca-o.

    ./mint_tokens.sh /tmp/notes-api-seguranca.env
    set -a; . /tmp/notes-api-seguranca.env; set +a
    python3 -m unittest -v test_security

Uma falha pode querer dizer duas coisas diferentes, e o nome do teste diz qual:
  LACUNA_  -> o teste exige o que foi pedido, a API nao o faz, e isso e o achado
  (resto)  -> a API devia fazer isto e, se falhar, e uma regressao
"""

import base64
import hashlib
import hmac
import json
import os
import re
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from guardrails import (BASE_URL, KEYCLOAK_URL, REALM, TIMEOUT, pedir,
                        procurar_fugas)

A = os.environ.get("TOKEN_SERVICO_A", "")
B = os.environ.get("TOKEN_SERVICO_B", "")
EXPIRADO = os.environ.get("TOKEN_EXPIRADO", "")
HUMANO_ADMIN = os.environ.get("TOKEN_HUMANO_ADMIN", "")
HUMANO_LEAD = os.environ.get("TOKEN_HUMANO_LEAD", "")
APP_LOG = os.environ.get("APP_LOG", "")

PAYLOADS_INJECAO = [
    ("sql classico",      "' OR 1=1--"),
    ("sql union",         "x' UNION SELECT table_name FROM information_schema.tables--"),
    ("sql destrutivo",    "x'; DROP TABLE note;--"),
    ("sql com delay",     "x' AND pg_sleep(5)--"),
    ("comando shell",     "x; cat /etc/passwd"),
    ("comando em subshell", "x$(id)"),
    ("comando com pipe",  "x | whoami"),
    ("path traversal",    "../../../../etc/passwd"),
    ("path traversal cod", "..%2f..%2f..%2fetc%2fpasswd"),
    ("expressao spel",    "#{7*7}"),
    ("template",          "${7*7}"),
    ("log4shell",         "${jndi:ldap://127.0.0.1/x}"),
]


def _b64u(bruto):
    return base64.urlsafe_b64encode(bruto).rstrip(b"=").decode()


def _b64u_dec(texto):
    return base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))


def claims(token):
    return json.loads(_b64u_dec(token.split(".")[1]))


def ids_existentes():
    """Ids visiveis ao exportador, que ve a tabela toda."""
    r = pedir("GET", "/notes", token=A)
    return [n["id"] for n in r.json()] if r.status_code == 200 else []


class T02_BFLA(unittest.TestCase):
    """Teste 2 -- escrita e funcoes administrativas com um token de leitura."""

    def test_escrita_recusada_em_todos_os_endpoints(self):
        ids = ids_existentes()
        alvo = ids[0] if ids else 1
        casos = [("POST", "/notes", '{"title":"x","body":"y"}'),
                 ("PUT", "/notes/%d" % alvo, '{"title":"x","body":"y"}'),
                 ("DELETE", "/notes/%d" % alvo, None)]
        for metodo, caminho, corpo in casos:
            with self.subTest(pedido="%s %s" % (metodo, caminho)):
                r = pedir(metodo, caminho, token=A, corpo=corpo)
                self.assertEqual(403, r.status_code)
                self.assertEqual({"error": "forbidden"}, r.json())

    def test_rotas_administrativas_nao_existem_nem_respondem(self):
        for caminho in ["/usuarios", "/users", "/configuracoes", "/config",
                        "/admin", "/notes/all", "/api/v1/dados"]:
            with self.subTest(caminho=caminho):
                r = pedir("GET", caminho, token=A)
                self.assertIn(r.status_code, (400, 401, 403, 404, 405),
                              "rota inesperadamente viva")
                self.assertNotEqual(200, r.status_code)

    def test_sem_token_e_401(self):
        r = pedir("GET", "/notes")
        self.assertEqual(401, r.status_code)
        self.assertEqual("Bearer", r.headers.get("WWW-Authenticate"))


class T03_LACUNA_limitacao_de_ritmo(unittest.TestCase):
    """Teste 3 -- 100 pedidos em 10 segundos devem comecar a receber 429."""

    def test_cem_pedidos_devem_ser_travados(self):
        inicio = time.time()
        with ThreadPoolExecutor(max_workers=10) as pool:
            futuros = [pool.submit(pedir, "GET", "/notes", A) for _ in range(100)]
            respostas = [f.result() for f in futuros]
        decorrido = time.time() - inicio
        codigos = {}
        for r in respostas:
            codigos[r.status_code] = codigos.get(r.status_code, 0) + 1
        print("\n    100 pedidos em %.1fs -> %s" % (decorrido, codigos))
        self.assertLess(decorrido, 10, "a rajada nem chegou a caber em 10s")
        self.assertIn(429, codigos,
                      "nenhum 429 em 100 pedidos: nao existe limitacao de ritmo")


class T04_BOLA_e_validacao_de_jwt(unittest.TestCase):
    """Teste 4 -- dados de outro cliente, e tokens que nao deviam servir."""

    def test_servico_b_nao_ve_a_listagem(self):
        r = pedir("GET", "/notes", token=B)
        self.assertEqual(200, r.status_code)
        self.assertEqual([], r.json(),
                         "o servico B recebeu notas que nao lhe pertencem")

    def test_servico_b_nao_alcanca_nenhum_registo(self):
        """403 e nao 404: o B nao tem app-user, logo o @PreAuthorize corta-o
        antes de haver registo nenhum em jogo. Uniforme para qualquer id, por
        isso nao serve de oraculo de existencia."""
        for ident in ids_existentes() + [99999999]:
            with self.subTest(id=ident):
                r = pedir("GET", "/notes/%d" % ident, token=B)
                self.assertEqual(403, r.status_code)

    # O JwtTimestampValidator do Spring aceita um token ate 60s depois do exp,
    # para tolerar desvio de relogio entre servidores. Nao e configurado aqui,
    # e o valor por omissao. O teste tem de esperar essa janela, senao acusa
    # de falha o que e uma tolerancia deliberada.
    DESVIO_DE_RELOGIO = 60

    @unittest.skipUnless(EXPIRADO, "sem TOKEN_EXPIRADO")
    def test_token_expirado_e_401(self):
        passou = time.time() - claims(EXPIRADO)["exp"]
        if passou < self.DESVIO_DE_RELOGIO:
            self.skipTest("expirado ha %ds; o desvio de relogio por omissao e "
                          "de %ds, volta a correr dentro de %ds"
                          % (passou, self.DESVIO_DE_RELOGIO,
                             self.DESVIO_DE_RELOGIO - passou))
        r = pedir("GET", "/notes", token=EXPIRADO)
        self.assertEqual(401, r.status_code)

    @unittest.skipUnless(EXPIRADO, "sem TOKEN_EXPIRADO")
    def test_a_janela_de_desvio_de_relogio_nao_passa_de_um_minuto(self):
        """Informativo: mede ate onde o exp e tolerado. Nao e uma falha, mas
        prolonga a vida util de um token roubado em 60s."""
        passou = time.time() - claims(EXPIRADO)["exp"]
        r = pedir("GET", "/notes", token=EXPIRADO)
        print("\n    expirado ha %ds -> HTTP %d" % (passou, r.status_code))
        if passou < self.DESVIO_DE_RELOGIO:
            self.assertEqual(200, r.status_code,
                             "recusado dentro da janela de desvio: o desvio foi reduzido")
        else:
            self.assertEqual(401, r.status_code)

    def test_assinatura_adulterada_e_401(self):
        """Troca-se um caractere do MEIO da assinatura. O ultimo nao serve: em
        base64url o caractere final carrega bits que nao sao usados, e trocá-lo
        pode descodificar para exatamente os mesmos bytes."""
        cabeca, carga, assinatura = A.split(".")
        meio = len(assinatura) // 2
        trocado = "A" if assinatura[meio] != "A" else "B"
        adulterada = assinatura[:meio] + trocado + assinatura[meio + 1:]
        self.assertNotEqual(_b64u_dec(assinatura), _b64u_dec(adulterada),
                            "a troca nao alterou os bytes da assinatura")
        r = pedir("GET", "/notes", token="%s.%s.%s" % (cabeca, carga, adulterada))
        self.assertEqual(401, r.status_code)

    def test_assinatura_removida_e_401(self):
        cabeca, carga, _ = A.split(".")
        r = pedir("GET", "/notes", token="%s.%s." % (cabeca, carga))
        self.assertEqual(401, r.status_code)

    def test_carga_adulterada_e_401(self):
        """Mudar uma claim sem poder reassinar: a assinatura deixa de bater."""
        c = claims(A)
        c["realm_access"] = {"roles": ["app-admin"]}
        cabeca, _, assinatura = A.split(".")
        forjado = "%s.%s.%s" % (cabeca, _b64u(json.dumps(c).encode()), assinatura)
        r = pedir("GET", "/notes", token=forjado)
        self.assertEqual(401, r.status_code)


class T05_LACUNA_registo_e_monitorizacao(unittest.TestCase):
    """Teste 5 -- o log tem de identificar data, hora, IP, rota, metodo,
    status e o servico, tanto num pedido valido como num recusado."""

    EXIGIDOS = ["data", "hora", "IP de origem", "rota", "metodo",
                "status HTTP", "identificador do servico"]

    @classmethod
    def setUpClass(cls):
        if not APP_LOG or not os.path.exists(APP_LOG):
            raise unittest.SkipTest("APP_LOG nao aponta para um ficheiro legivel")
        cls.posicao = os.path.getsize(APP_LOG)
        ids = ids_existentes()
        cls.valido = pedir("GET", "/notes", token=A)
        cls.recusado = pedir("DELETE", "/notes/%d" % (ids[0] if ids else 1), token=A)
        time.sleep(0.5)
        with open(APP_LOG, errors="replace") as f:
            f.seek(cls.posicao)
            cls.novas = f.read()

    def _presentes(self, trecho):
        azp = claims(A).get("azp", "")
        sub = claims(A).get("sub", "")
        return {
            "data": bool(re.search(r"\d{4}-\d{2}-\d{2}", trecho)),
            "hora": bool(re.search(r"\d{2}:\d{2}:\d{2}", trecho)),
            "IP de origem": bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b::1\b", trecho)),
            "rota": "/notes" in trecho,
            "metodo": bool(re.search(r"\b(GET|POST|PUT|DELETE)\b", trecho)),
            "status HTTP": bool(re.search(r"\b(200|204|401|403|404)\b", trecho)),
            "identificador do servico": (azp in trecho) or (sub in trecho),
        }

    def test_pedido_valido_fica_rastreavel(self):
        """A linha canonica por pedido vem do RegistoDePedidosFilter; a do
        NoteService continua a existir mas so conta o que foi devolvido."""
        self.assertEqual(200, self.valido.status_code)
        linhas = [l for l in self.novas.splitlines()
                  if "pedido: GET /notes 200" in l]
        self.assertTrue(linhas, "o pedido valido nao deixou nenhuma linha de log")
        presentes = self._presentes("\n".join(linhas))
        print("\n    pedido valido  -> " + ", ".join(
            "%s:%s" % (k, "sim" if v else "NAO") for k, v in presentes.items()))
        faltam = [k for k in self.EXIGIDOS if not presentes[k]]
        self.assertFalse(faltam, "o log do pedido valido nao tem: %s" % ", ".join(faltam))

    def test_pedido_recusado_fica_rastreavel(self):
        self.assertEqual(403, self.recusado.status_code)
        linhas = [l for l in self.novas.splitlines()
                  if "pedido: DELETE /notes" in l and " 403 " in l]
        self.assertTrue(linhas, "o 403 nao deixou nenhuma linha de log")
        presentes = self._presentes("\n".join(linhas))
        print("\n    pedido recusado -> " + ", ".join(
            "%s:%s" % (k, "sim" if v else "NAO") for k, v in presentes.items()))
        faltam = [k for k in self.EXIGIDOS if not presentes[k]]
        self.assertFalse(faltam, "o log do 403 nao tem: %s" % ", ".join(faltam))

    def test_o_motivo_fica_no_log_e_nao_na_resposta(self):
        """O que deve mesmo acontecer: o corpo e generico, o log e especifico."""
        self.assertEqual({"error": "forbidden"}, self.recusado.json())
        self.assertIn("403", self.novas)


class T06_deputado_confuso(unittest.TestCase):
    """Teste 6 -- injecao de parametros e validacao de origem."""

    def test_payloads_nos_corpos_param_antes_da_validacao(self):
        """A guarda dispara antes de o corpo ser lido: 403, nunca 500."""
        for nome, payload in PAYLOADS_INJECAO:
            with self.subTest(payload=nome):
                corpo = json.dumps({"title": payload, "body": payload})
                r = pedir("POST", "/notes", token=A, corpo=corpo)
                self.assertEqual(403, r.status_code)

    def test_payloads_no_caminho_nunca_rebentam(self):
        for nome, payload in PAYLOADS_INJECAO:
            with self.subTest(payload=nome):
                r = pedir("GET", "/notes/" + requests.utils.quote(payload, safe=""), token=A)
                # 400: o id nao converte para Long. 401: o caminho foi recusado
                # antes do controller e o reencaminhamento para /error, que
                # tambem exige autenticacao, respondeu por ele.
                self.assertIn(r.status_code, (400, 401, 403, 404),
                              "estado inesperado para um id invalido")

    @unittest.skipUnless(HUMANO_ADMIN, "sem TOKEN_HUMANO_ADMIN")
    def test_sql_injection_com_token_de_escrita_e_tratada_como_texto(self):
        """Quem PODE escrever manda SQL: tem de ficar guardado como texto."""
        antes = len(ids_existentes())
        for nome, payload in PAYLOADS_INJECAO:
            with self.subTest(payload=nome):
                corpo = json.dumps({"title": payload, "body": payload})
                r = pedir("POST", "/notes", token=HUMANO_ADMIN, corpo=corpo)
                self.assertIn(r.status_code, (201, 400, 422),
                              "estado inesperado a criar com payload")
                if r.status_code != 201:
                    continue
                # O payload tem de voltar igual: guardado como texto, nao executado.
                self.assertEqual(payload, r.json()["title"],
                                 "o payload foi reinterpretado em vez de guardado")
                # Apagada logo, para o varrimento de fugas nao a confundir
                # com SQL vindo do servidor nas listagens seguintes.
                apagar = pedir("DELETE", "/notes/%d" % r.json()["id"], token=HUMANO_ADMIN)
                self.assertEqual(204, apagar.status_code)
        # A tabela tem de continuar la depois do DROP TABLE e do pg_sleep.
        self.assertEqual(antes, len(ids_existentes()),
                         "a tabela note nao voltou ao estado inicial")

    @unittest.skipUnless(HUMANO_ADMIN, "sem TOKEN_HUMANO_ADMIN")
    def test_byte_nulo_no_titulo_nao_pode_dar_500(self):
        """O Postgres recusa 0x00 em colunas de texto e nada o filtra antes."""
        corpo = json.dumps({"title": "x\u0000y", "body": "x"})
        r = pedir("POST", "/notes", token=HUMANO_ADMIN, corpo=corpo)
        if r.status_code == 201:
            pedir("DELETE", "/notes/%d" % r.json()["id"], token=HUMANO_ADMIN)
        self.assertIn(r.status_code, (201, 400, 422),
                      "um byte nulo devia ser filtrado ou recusado na validacao")

    def test_LACUNA_origem_de_rede_nao_autorizada(self):
        """Pedido valido a dizer que vem de um IP fora de qualquer lista."""
        cabecalhos = {"X-Forwarded-For": "10.0.0.99",
                      "X-Real-IP": "10.0.0.99",
                      "Forwarded": "for=10.0.0.99;proto=http",
                      "X-Originating-IP": "10.0.0.99"}
        r = pedir("GET", "/notes", token=A, cabecalhos=cabecalhos)
        self.assertEqual(403, r.status_code,
                         "a API nao valida a origem do pedido: nao existe lista branca de rede")


class T07_autorizacao_vertical_e_horizontal(unittest.TestCase):
    """Teste 7 -- metodos trocados, mass assignment e isolamento entre pares."""

    def test_metodos_nao_permitidos_nas_rotas_erradas(self):
        ids = ids_existentes()
        alvo = ids[0] if ids else 1
        for metodo, caminho in [("POST", "/notes/%d" % alvo),
                                ("PUT", "/notes"),
                                ("DELETE", "/notes"),
                                ("PATCH", "/notes/%d" % alvo)]:
            with self.subTest(pedido="%s %s" % (metodo, caminho)):
                r = pedir(metodo, caminho, token=A, corpo='{"title":"x"}')
                self.assertIn(r.status_code, (403, 405),
                              "metodo aceite numa rota que nao o declara")

    @unittest.skipUnless(HUMANO_ADMIN, "sem TOKEN_HUMANO_ADMIN")
    def test_mass_assignment_e_ignorado(self):
        eu = claims(HUMANO_ADMIN)
        corpo = json.dumps({
            "title": "nota de teste de mass assignment",
            "body": "corpo",
            "id": 999999,
            "ownerId": "00000000-0000-0000-0000-000000000000",
            "teamId": "team-inexistente",
            "createdAt": "1990-01-01T00:00:00",
            "role": "admin",
            "is_admin": True,
            "roles": ["app-admin"],
            "authorities": ["ROLE_app-admin"],
        })
        r = pedir("POST", "/notes", token=HUMANO_ADMIN, corpo=corpo)
        self.assertEqual(201, r.status_code)
        nota = r.json()
        try:
            self.assertEqual(eu["sub"], nota["ownerId"], "ownerId veio do pedido")
            self.assertEqual(eu["teams"][0], nota["teamId"], "teamId veio do pedido")
            self.assertNotEqual(999999, nota["id"], "o id foi imposto pelo pedido")
            self.assertNotIn("1990", nota["createdAt"], "createdAt veio do pedido")
            for extra in ("role", "is_admin", "roles", "authorities"):
                self.assertNotIn(extra, nota, "campo privilegiado %r sobreviveu" % extra)
        finally:
            pedir("DELETE", "/notes/%d" % nota["id"], token=HUMANO_ADMIN)

    @unittest.skipUnless(HUMANO_LEAD and HUMANO_ADMIN, "sem os dois tokens humanos")
    def test_isolamento_horizontal_entre_equipas(self):
        lead, admin = claims(HUMANO_LEAD), claims(HUMANO_ADMIN)
        self.assertNotEqual(lead["teams"], admin["teams"], "os dois estao na mesma equipa")
        r = pedir("POST", "/notes", token=HUMANO_ADMIN,
                  corpo='{"title":"nota privada da equipa B","body":"x"}')
        self.assertEqual(201, r.status_code)
        alheia = r.json()["id"]
        try:
            for metodo, esperado in [("GET", 404), ("PUT", 404), ("DELETE", 404)]:
                with self.subTest(metodo=metodo):
                    r = pedir(metodo, "/notes/%d" % alheia, token=HUMANO_LEAD,
                              corpo='{"title":"tomada","body":"x"}')
                    self.assertEqual(esperado, r.status_code)
            # E o 404 de "nao existe" tem de ser indistinguivel do de "nao ves".
            inexistente = pedir("GET", "/notes/99999999", token=HUMANO_LEAD)
            escondida = pedir("GET", "/notes/%d" % alheia, token=HUMANO_LEAD)
            self.assertEqual(inexistente.status_code, escondida.status_code)
            self.assertEqual(inexistente.text, escondida.text)
        finally:
            pedir("DELETE", "/notes/%d" % alheia, token=HUMANO_ADMIN)


class T08_ligacao_entre_a_role_e_o_azp(unittest.TestCase):
    """O ehServico() exige role E azp. O servico B tem a role e o azp errado."""

    def test_os_dois_servicos_tem_a_mesma_role(self):
        papeis = lambda t: set(claims(t)["realm_access"]["roles"])
        self.assertIn("app-notes-exporter", papeis(A))
        self.assertIn("app-notes-exporter", papeis(B))
        self.assertNotEqual(claims(A)["azp"], claims(B)["azp"])

    def test_a_role_sozinha_nao_abre_a_leitura_total(self):
        de_a = pedir("GET", "/notes", token=A)
        de_b = pedir("GET", "/notes", token=B)
        self.assertEqual(200, de_a.status_code)
        self.assertEqual(200, de_b.status_code)
        self.assertGreater(len(de_a.json()), 0, "o exportador devia ver notas")
        self.assertEqual([], de_b.json(),
                         "a role sozinha abriu a leitura total: o azp nao esta a travar")


class T09_OWASP_API2_tokens_forjados(unittest.TestCase):
    """Alem de expirado e adulterado: tokens forjados de raiz."""

    @classmethod
    def setUpClass(cls):
        jwks = requests.get("%s/realms/%s/protocol/openid-connect/certs"
                            % (KEYCLOAK_URL, REALM), timeout=TIMEOUT).json()
        chave = next(k for k in jwks["keys"]
                     if k.get("alg") == "RS256" and k.get("use") == "sig")
        n = int.from_bytes(_b64u_dec(chave["n"]), "big")
        e = int.from_bytes(_b64u_dec(chave["e"]), "big")
        cls.publica_pem = rsa.RSAPublicNumbers(e, n).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.kid = chave["kid"]
        cls.carga = dict(claims(A))
        cls.carga["exp"] = int(time.time()) + 3600
        cls.carga["realm_access"] = {"roles": ["app-admin", "app-user"]}

    def _montar(self, cabeca, chave_hmac=None):
        c = _b64u(json.dumps(cabeca, separators=(",", ":")).encode())
        p = _b64u(json.dumps(self.carga, separators=(",", ":")).encode())
        if chave_hmac is None:
            return "%s.%s." % (c, p)
        mac = hmac.new(chave_hmac, ("%s.%s" % (c, p)).encode(), hashlib.sha256).digest()
        return "%s.%s.%s" % (c, p, _b64u(mac))

    def test_alg_none_e_recusado(self):
        for alg in ("none", "None", "NONE", "nOnE"):
            with self.subTest(alg=alg):
                r = pedir("GET", "/notes",
                          token=self._montar({"alg": alg, "typ": "JWT"}))
                self.assertEqual(401, r.status_code)

    def test_confusao_de_algoritmo_com_a_chave_publica_e_recusada(self):
        """O ataque classico: HS256 usando a chave publica do realm como segredo."""
        r = pedir("GET", "/notes", token=self._montar(
            {"alg": "HS256", "typ": "JWT", "kid": self.kid}, self.publica_pem))
        self.assertEqual(401, r.status_code)

    def test_hs256_com_chave_arbitraria_e_recusado(self):
        r = pedir("GET", "/notes", token=self._montar(
            {"alg": "HS256", "typ": "JWT", "kid": self.kid}, b"segredo-inventado"))
        self.assertEqual(401, r.status_code)

    def test_rs256_com_chave_propria_e_recusado(self):
        """Estrutura perfeita, assinatura valida, chave errada."""
        privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        c = _b64u(json.dumps({"alg": "RS256", "typ": "JWT", "kid": self.kid}).encode())
        p = _b64u(json.dumps(self.carga).encode())
        assinatura = privada.sign(("%s.%s" % (c, p)).encode(),
                                  padding.PKCS1v15(), hashes.SHA256())
        r = pedir("GET", "/notes", token="%s.%s.%s" % (c, p, _b64u(assinatura)))
        self.assertEqual(401, r.status_code)

    def test_kid_inexistente_e_recusado(self):
        privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        c = _b64u(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "chave-que-nao-existe"}).encode())
        p = _b64u(json.dumps(self.carga).encode())
        assinatura = privada.sign(("%s.%s" % (c, p)).encode(),
                                  padding.PKCS1v15(), hashes.SHA256())
        r = pedir("GET", "/notes", token="%s.%s.%s" % (c, p, _b64u(assinatura)))
        self.assertEqual(401, r.status_code)

    def test_lixo_no_lugar_do_token(self):
        for token in ["", "abc", "a.b.c", "Bearer", "." * 10, "null", "undefined",
                      _b64u(b"{}") + "." + _b64u(b"{}") + ".x"]:
            with self.subTest(token=token[:12]):
                r = pedir("GET", "/notes", token=token or None)
                self.assertEqual(401, r.status_code)


class T10_OWASP_API8_superficie_do_actuator(unittest.TestCase):
    """O /actuator/health e o unico caminho aberto. O que e que ele deixa passar?"""

    FECHADOS = ["/actuator", "/actuator/env", "/actuator/env/PATH", "/actuator/beans",
                "/actuator/configprops", "/actuator/heapdump", "/actuator/threaddump",
                "/actuator/mappings", "/actuator/metrics", "/actuator/loggers",
                "/actuator/shutdown", "/actuator/info", "/actuator/prometheus",
                "/actuator/caches", "/actuator/scheduledtasks", "/actuator/sessions"]

    CONTORNOS = ["/actuator/health/../env", "/actuator/health/%2e%2e/env",
                 "/actuator/health/..%2fenv", "/actuator/health/..;/env",
                 "/actuator/./health/../env", "/actuator/health%2f..%2fenv",
                 "/ACTUATOR/HEALTH", "/Actuator/Env", "//actuator//env",
                 "/actuator//env", "/actuator/env;", "/actuator/env/",
                 "/actuator/env;x=/actuator/health", "/actuator/env?x=/actuator/health",
                 "/actuator/env%00/actuator/health", "/actuator/env#/actuator/health",
                 "/actuator/health/../../actuator/env", "/./actuator/env",
                 "/actuator/env.json", "/actuator/env/"]

    def test_health_esta_aberto_e_diz_o_minimo(self):
        r = pedir("GET", "/actuator/health")
        self.assertEqual(200, r.status_code)
        corpo = r.json()
        self.assertEqual({"status"}, set(corpo),
                         "o health expoe mais do que o estado: %s" % sorted(corpo))
        for proibido in ("components", "details", "diskSpace", "db", "free", "total",
                         "validationQuery", "database", "hello"):
            self.assertNotIn(proibido, r.text)

    def test_sub_caminhos_do_health_nao_detalham_nada(self):
        for caminho in ["/actuator/health/db", "/actuator/health/diskSpace",
                        "/actuator/health/ping", "/actuator/health/readiness",
                        "/actuator/health/liveness"]:
            with self.subTest(caminho=caminho):
                r = pedir("GET", caminho)
                print("\n    %-34s -> %d %s" % (caminho, r.status_code, r.text[:70]))
                if r.status_code == 200:
                    self.assertEqual({"status"}, set(r.json()),
                                     "%s detalha o componente" % caminho)

    def test_restantes_endpoints_sem_token(self):
        for caminho in self.FECHADOS:
            with self.subTest(caminho=caminho):
                r = pedir("GET", caminho)
                self.assertNotEqual(200, r.status_code, "%s esta aberto" % caminho)
                self.assertIn(r.status_code, (401, 404))

    def test_restantes_endpoints_com_token_de_servico(self):
        """Segunda camada: mesmo autenticado, estes endpoints nao estao expostos."""
        for caminho in self.FECHADOS:
            with self.subTest(caminho=caminho):
                r = pedir("GET", caminho, token=A)
                self.assertNotEqual(200, r.status_code, "%s responde a um token" % caminho)

    def test_contornos_do_matcher_de_caminhos(self):
        for caminho in self.CONTORNOS:
            with self.subTest(caminho=caminho):
                r = pedir("GET", caminho)
                if r.status_code == 200:
                    # 200 so e aceitavel se o que respondeu foi o proprio health.
                    self.assertEqual({"status"}, set(r.json()),
                                     "%s devolveu 200 com conteudo que nao e o health" % caminho)

    def test_metodos_estranhos_no_health(self):
        for metodo in ("POST", "PUT", "DELETE", "TRACE", "PATCH"):
            with self.subTest(metodo=metodo):
                r = pedir(metodo, "/actuator/health")
                self.assertNotEqual(200, r.status_code,
                                    "o health aceita %s" % metodo)


class T11_OWASP_API4_consumo_de_recursos(unittest.TestCase):
    """Alem do ritmo: tamanho da resposta e tamanho do pedido."""

    def test_LACUNA_listagem_nao_tem_paginacao(self):
        r = pedir("GET", "/notes?page=0&size=1&limit=1&offset=0", token=A)
        self.assertEqual(200, r.status_code)
        self.assertLessEqual(len(r.json()), 1,
                             "a listagem ignora paginacao e devolve a tabela toda")

    @unittest.skipUnless(HUMANO_ADMIN, "sem TOKEN_HUMANO_ADMIN")
    def test_titulo_acima_do_limite_da_coluna_nao_pode_dar_500(self):
        """title e VARCHAR(255) na base de dados e so tem @NotBlank no DTO."""
        corpo = json.dumps({"title": "A" * 300, "body": "x"})
        r = pedir("POST", "/notes", token=HUMANO_ADMIN, corpo=corpo)
        if r.status_code == 201:
            pedir("DELETE", "/notes/%d" % r.json()["id"], token=HUMANO_ADMIN)
        self.assertIn(r.status_code, (400, 413, 422),
                      "um titulo acima de 255 devia ser recusado na validacao")

    @unittest.skipUnless(HUMANO_ADMIN, "sem TOKEN_HUMANO_ADMIN")
    def test_corpo_enorme_nao_pode_dar_500(self):
        corpo = json.dumps({"title": "carga", "body": "A" * (4 * 1024 * 1024)})
        r = pedir("POST", "/notes", token=HUMANO_ADMIN, corpo=corpo)
        if r.status_code == 201:
            pedir("DELETE", "/notes/%d" % r.json()["id"], token=HUMANO_ADMIN)
        print("\n    corpo de 4 MiB -> HTTP %d" % r.status_code)
        self.assertIn(r.status_code, (201, 400, 413, 422))


class T12_OWASP_API9_inventario(unittest.TestCase):
    """Clientes e superficie que existem no realm sem estarem no Terraform."""

    def _grant_de_password(self, client_id):
        return requests.post(
            "%s/realms/%s/protocol/openid-connect/token" % (KEYCLOAK_URL, REALM),
            data={"grant_type": "password", "client_id": client_id,
                  "username": "ana.pinto",
                  "password": os.environ.get("PW_UTILIZADORES", "x")},
            timeout=TIMEOUT)

    def test_admin_cli_aceita_grant_de_password(self):
        """Documenta o estado, sem o julgar: o admin-cli emite tokens deste
        realm por password e nao esta no Terraform. Nao e removivel sem
        importar um cliente que o Terraform nao possui; a mitigacao e tornar
        o oraculo caro, nao fecha-lo -- ver o teste do bloqueio abaixo."""
        r = self._grant_de_password("admin-cli")
        print("\n    admin-cli com password valida -> HTTP %d" % r.status_code)
        self.assertIn(r.status_code, (200, 401),
                      "estado inesperado do grant de password")

    def test_tentativas_repetidas_bloqueiam_a_conta(self):
        """A mitigacao do oraculo de passwords: brute_force_detection no realm.

        Usa a maria.santos de proposito, que nenhum outro teste usa: a conta
        fica bloqueada ate 15 minutos depois de correr isto.
        """
        VITIMA = "maria.santos"
        certa = os.environ.get("PW_UTILIZADORES", "")
        if not certa:
            self.skipTest("sem PW_UTILIZADORES")

        def tentar(password):
            return requests.post(
                "%s/realms/%s/protocol/openid-connect/token" % (KEYCLOAK_URL, REALM),
                data={"grant_type": "password", "client_id": "admin-cli",
                      "username": VITIMA, "password": password},
                timeout=TIMEOUT)

        # Controlo: a conta tem de estar utilizavel antes do ataque.
        antes = tentar(certa)
        if antes.status_code != 200:
            self.skipTest("a %s ja esta bloqueada de uma corrida anterior; "
                          "espera 15 minutos" % VITIMA)

        # O ataque: passwords erradas em serie.
        for i in range(40):
            resposta = tentar("errada-%d" % i)
            if resposta.status_code == 200:
                self.fail("uma password errada foi aceite")

        # A prova: a password CERTA passa a ser recusada.
        depois = tentar(certa)
        print("\n    apos 40 tentativas, a password certa -> HTTP %d" % depois.status_code)
        self.assertNotEqual(200, depois.status_code,
                            "a conta nao foi bloqueada: brute_force_detection "
                            "nao esta ativo no realm")

        # E o bloqueio nao pode criar um oraculo novo: a resposta da conta
        # bloqueada tem de ser igual a de uma password errada.
        errada = tentar("ainda-outra-errada")
        self.assertEqual(errada.status_code, depois.status_code)
        self.assertEqual(errada.json().get("error"), depois.json().get("error"))

    def test_token_do_admin_cli_e_recusado_pela_api(self):
        """A mitigacao: mesmo que o Keycloak o emita, a API nao o aceita."""
        r = self._grant_de_password("admin-cli")
        if r.status_code != 200:
            self.skipTest("o admin-cli nao emitiu token")
        resposta = pedir("GET", "/notes", token=r.json()["access_token"])
        self.assertEqual(401, resposta.status_code)

    def test_descoberta_nao_expoe_mais_do_que_o_necessario(self):
        r = requests.get("%s/realms/%s/.well-known/openid-configuration"
                         % (KEYCLOAK_URL, REALM), timeout=TIMEOUT)
        self.assertEqual(200, r.status_code)
        doc = r.json()
        print("\n    grant_types_supported -> %s" % doc.get("grant_types_supported"))
        self.assertNotIn("implicit", doc.get("grant_types_supported", []),
                         "o realm anuncia o fluxo implicito")


class T13_OWASP_API3_exposicao_de_dados(unittest.TestCase):
    """Que campos saem na resposta, para alem dos necessarios."""

    def test_LACUNA_resposta_expoe_identificadores_internos(self):
        r = pedir("GET", "/notes", token=A)
        self.assertEqual(200, r.status_code)
        notas = r.json()
        if not notas:
            self.skipTest("sem notas para inspecionar")
        uuid = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                          r"[0-9a-f]{4}-[0-9a-f]{12}\b")
        com_uuid = [n["id"] for n in notas if uuid.search(json.dumps(n))]
        self.assertFalse(com_uuid,
                         "o ownerId e o sub do Keycloak e vai em claro nas notas %s"
                         % com_uuid)

    def test_cabecalhos_nao_revelam_a_pilha(self):
        r = pedir("GET", "/notes", token=A)
        for cabecalho in ("Server", "X-Powered-By", "X-Application-Context"):
            valor = r.headers.get(cabecalho, "")
            with self.subTest(cabecalho=cabecalho):
                self.assertNotRegex(valor, r"(?i)tomcat|spring|boot|jetty|\d+\.\d+",
                                    "%s revela a pilha: %r" % (cabecalho, valor))


if __name__ == "__main__":
    unittest.main(verbosity=2)
