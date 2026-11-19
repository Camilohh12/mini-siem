#!/usr/bin/env python3
"""Simula los ataques que el agente debe detectar (solo para tu entorno de prueba).

Uso (con el stack levantado y TRUST_PROXY=true en .env):

    python scripts/simular_ataques.py            # todos los escenarios
    python scripts/simular_ataques.py tokens bd  # solo algunos

Escenarios: fuerza_bruta, viaje, horario, tokens, bd
No necesita instalar nada: usa solo la biblioteca estándar y `docker exec`.
"""

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE = "http://localhost:8000"
RAIZ = Path(__file__).resolve().parent.parent

# IPs públicas de ejemplo para simular el origen (vía X-Forwarded-For).
IP_MEXICO = "132.248.10.44"    # red de la UNAM, Ciudad de México
IP_EUROPA = "129.187.254.11"   # centro de cómputo LRZ, Múnich
IP_ATACANTE = "203.0.113.50"   # rango reservado para documentación
IP_ATACANTE_2 = "203.0.113.77"


def leer_env() -> dict:
    valores = {}
    archivo = RAIZ / ".env"
    if archivo.exists():
        for linea in archivo.read_text(encoding="utf-8").splitlines():
            if "=" in linea and not linea.lstrip().startswith("#"):
                clave, _, valor = linea.partition("=")
                valores[clave.strip()] = valor.strip()
    return valores


ENV = leer_env()


def peticion(metodo: str, ruta: str, ip: str, cuerpo: dict | None = None, token: str | None = None,
             agente: str = "Mozilla/5.0 (simulador)") -> tuple[int, dict]:
    cabeceras = {"X-Forwarded-For": ip, "User-Agent": agente, "Content-Type": "application/json"}
    if token:
        cabeceras["Authorization"] = f"Bearer {token}"
    datos = json.dumps(cuerpo).encode() if cuerpo is not None else None
    req = urllib.request.Request(BASE + ruta, data=datos, headers=cabeceras, method=metodo)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def login(usuario: str, password: str, ip: str, **kw) -> tuple[int, dict]:
    return peticion("POST", "/login", ip, {"usuario": usuario, "password": password}, **kw)


def docker(*args: str, entrada: str | None = None, env: dict | None = None) -> subprocess.CompletedProcess:
    cmd = ["docker", "exec"]
    if entrada is not None:
        cmd.append("-i")
    for clave, valor in (env or {}).items():
        cmd += ["-e", f"{clave}={valor}"]
    return subprocess.run(cmd + list(args), input=entrada, text=True, capture_output=True)


def titulo(texto: str) -> None:
    print(f"\n=== {texto} ===")


# ── Escenarios ───────────────────────────────────────────────────────────────
def fuerza_bruta():
    titulo("Fuerza bruta: 7 logins fallidos desde la misma IP  ->  FUERZA_BRUTA")
    for i in range(7):
        codigo, _ = login("admin", f"clave-incorrecta-{i}", IP_ATACANTE)
        print(f"  intento {i + 1}: HTTP {codigo}")


def viaje():
    titulo("Viaje imposible: maria entra desde México y enseguida desde Europa  ->  VIAJE_IMPOSIBLE")
    print("  México:", login("maria", "Maria#2026", IP_MEXICO)[0])
    time.sleep(1)
    print("  Europa:", login("maria", "Maria#2026", IP_EUROPA)[0])


def horario():
    titulo("Horario inusual: login de admin a las 3:00 AM  ->  HORARIO_INUSUAL")
    # No se puede cambiar el reloj, así que se publica en Kafka un evento
    # fabricado con hora 03:00 de Ciudad de México (09:00 UTC).
    evento = {
        "event_id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).replace(hour=9, minute=0, second=0, microsecond=0).isoformat(),
        "origen": "simulador",
        "tipo": "login_success",
        "usuario": "admin",
        "rol": "admin",
        "ip": "10.0.0.5",
        "user_agent": "Mozilla/5.0 (simulador)",
    }
    r = docker(
        "siem-kafka", "/opt/kafka/bin/kafka-console-producer.sh",
        "--bootstrap-server", "localhost:9092", "--topic", "auth.events",
        entrada=json.dumps(evento) + "\n",
    )
    print("  evento publicado" if r.returncode == 0 else f"  ERROR: {r.stderr.strip()[:300]}")


def tokens():
    titulo("Tokens falsos: 5 peticiones con JWT inventado  ->  TOKENS_INVALIDOS")
    for i in range(5):
        codigo, _ = peticion("GET", "/perfil", IP_ATACANTE_2, token="eyJhbGciOiJIUzI1NiJ9.e30.firma-falsa")
        print(f"  intento {i + 1}: HTTP {codigo}")

    titulo("Robo de sesión: token emitido para una IP y usado desde otra  ->  TOKEN_OTRA_IP")
    codigo, cuerpo = login("maria", "Maria#2026", IP_MEXICO)
    if codigo != 200:
        print("  no se pudo iniciar sesión:", codigo, cuerpo)
        return
    print("  uso legítimo:", peticion("GET", "/perfil", IP_MEXICO, token=cuerpo["access_token"])[0])
    print("  uso desde otra IP:", peticion("GET", "/perfil", IP_ATACANTE, token=cuerpo["access_token"])[0])

    titulo("Herramienta de ataque: User-Agent de sqlmap  ->  USER_AGENT_SOSPECHOSO")
    print("  HTTP", login("admin", "x", IP_ATACANTE_2, agente="sqlmap/1.8 (https://sqlmap.org)")[0])


def bd():
    usuario_app = ENV.get("APP_DB_USER", "app_user")
    titulo(f"Escalada de privilegios: {usuario_app} intenta DROP TABLE  ->  ESCALADA_PRIVILEGIOS (+ CONEXION_DIRECTA)")
    r = docker(
        "siem-mysql", "mysql", f"-u{usuario_app}", "-h127.0.0.1", "-e", "DROP TABLE bddatos.tbusuarios",
        env={"MYSQL_PWD": ENV.get("APP_DB_PASSWORD", "")},
    )
    # Lo esperado es que MySQL lo rechace: la cuenta solo tiene SELECT.
    print("  MySQL respondió:", (r.stderr.strip() or "ejecutado")[:160])

    titulo("Extracción masiva: SELECT * de toda la tabla  ->  EXTRACCION_MASIVA")
    r = docker(
        "siem-mysql", "mysql", "-uroot", "-h127.0.0.1", "-e", "SELECT * FROM bddatos.tbusuarios",
        env={"MYSQL_PWD": ENV.get("MYSQL_ROOT_PASSWORD", "")},
    )
    print("  filas leídas:" if r.returncode == 0 else "  ERROR:", (len(r.stdout.splitlines()) - 1) if r.returncode == 0 else r.stderr.strip()[:160])


ESCENARIOS = {"fuerza_bruta": fuerza_bruta, "viaje": viaje, "horario": horario, "tokens": tokens, "bd": bd}

if __name__ == "__main__":
    elegidos = sys.argv[1:] or list(ESCENARIOS)
    desconocidos = [e for e in elegidos if e not in ESCENARIOS]
    if desconocidos:
        sys.exit(f"Escenario desconocido: {desconocidos}. Opciones: {', '.join(ESCENARIOS)}")
    try:
        peticion("GET", "/health", "127.0.0.1")
    except OSError:
        sys.exit(f"No se pudo conectar a {BASE}. ¿Está levantado el stack? (docker compose ps)")
    for nombre in elegidos:
        ESCENARIOS[nombre]()
    print("\nListo. Las alertas deberían llegar a Telegram en unos segundos.")
    print("También puedes verlas con:  docker compose logs security-agent | grep ALERTA")
