"""Recolector del log de auditoría de MySQL (productor de eventos).

MySQL (con --general-log=ON --log-output=TABLE) anota cada conexión y cada
sentencia en la tabla mysql.general_log. Este proceso lee las filas nuevas
cada pocos segundos y las publica en Kafka (topic db.audit):

  db_connect       alguien se conectó (o lo intentó) al motor
  db_query         alguien ejecutó una sentencia SQL
  db_log_alterado  el propio log fue vaciado o desactivado

La posición de lectura es el NÚMERO DE FILAS ya enviadas, no la hora de la
fila: MySQL escribe event_time en la zona horaria de la sesión que ejecuta la
sentencia, así que un atacante podría hacer `SET time_zone` para que sus
consultas parezcan antiguas y un lector basado en la hora no las vería.
"""

import json
import logging
import os
import re
import signal
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import mysql.connector
from confluent_kafka import Producer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("db-shipper")

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "mysql"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "audit_reader"),
    "password": os.environ["DB_PASSWORD"],
    "connection_timeout": 5,
    "autocommit": True,
}
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_TOPIC_DB = os.environ.get("KAFKA_TOPIC_DB", "db.audit")
INTERVALO_SEG = float(os.environ.get("INTERVALO_SEG", "2"))
ARCHIVO_ESTADO = Path(os.environ.get("ARCHIVO_ESTADO", "/state/posicion.json"))
# Cuentas técnicas cuyo ruido no se envía (el propio recolector y el healthcheck).
USUARIOS_IGNORADOS = {
    u.strip() for u in os.environ.get("USUARIOS_IGNORADOS", "audit_reader,healthcheck").split(",") if u.strip()
}
COMANDOS = {"Connect", "Query", "Execute"}
LOTE = 5000
MAX_SENTENCIA = 4000

# user_host tiene la forma:  app_user[app_user] @ host [172.28.0.20]
RE_USER_HOST = re.compile(r"^[^\[]*\[(?P<usuario>[^\]]*)\]\s*@\s*(?P<host>[^\[]*)\[(?P<ip>[^\]]*)\]")

# Sin ORDER BY: el motor CSV devuelve las filas en el orden en que se escribieron.
CONSULTA = """
    SELECT event_time, user_host, thread_id, command_type,
           CONVERT(argument USING utf8mb4) AS argumento
    FROM mysql.general_log
    LIMIT %s, %s
"""

activo = True


def detener(*_):
    global activo
    activo = False


def ahora_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def texto(valor) -> str:
    if isinstance(valor, (bytes, bytearray)):
        return valor.decode("utf-8", "replace")
    return valor or ""


def leer_posicion() -> int | None:
    try:
        return int(json.loads(ARCHIVO_ESTADO.read_text())["filas"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def guardar_posicion(filas: int) -> None:
    try:
        ARCHIVO_ESTADO.parent.mkdir(parents=True, exist_ok=True)
        ARCHIVO_ESTADO.write_text(json.dumps({"filas": filas}))
    except OSError as error:
        log.warning("No se pudo guardar la posición: %s", error)


def consultar(cnx, sql: str, parametros: tuple = ()) -> list:
    cursor = cnx.cursor()
    cursor.execute(sql, parametros)
    filas = cursor.fetchall()
    cursor.close()
    return filas


def a_evento(fila, desfase_utc: timedelta) -> dict | None:
    """Convierte una fila de general_log en un evento de auditoría."""
    event_time, user_host, thread_id, comando, argumento = fila
    comando, argumento = texto(comando), texto(argumento)
    m = RE_USER_HOST.match(texto(user_host))
    usuario = m.group("usuario") if m else ""
    if comando not in COMANDOS or usuario in USUARIOS_IGNORADOS:
        return None

    evento = {
        # Identificador determinista: si la fila se lee dos veces, el id se repite
        # y el almacén de auditoría descarta el duplicado.
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_OID, f"{event_time.isoformat()}|{thread_id}|{comando}|{argumento}")),
        # event_time viene en la hora local del servidor; se pasa a UTC.
        "ts": (event_time - desfase_utc).replace(tzinfo=timezone.utc).isoformat(timespec="milliseconds"),
        "origen": "mysql",
        "tipo": "db_connect" if comando == "Connect" else "db_query",
        "usuario_bd": usuario,
        "host": m.group("host").strip() if m else "",
        "ip": m.group("ip") if m else "",
        "thread_id": thread_id,
    }
    if comando == "Connect":
        evento["acceso_denegado"] = argumento.startswith("Access denied")
        evento["detalle"] = argumento[:300]
    else:
        evento["sentencia"] = argumento[:MAX_SENTENCIA]
    return evento


def evento_log_alterado(motivo: str, detalle: str) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "ts": ahora_iso(),
        "origen": "mysql",
        "tipo": "db_log_alterado",
        "motivo": motivo,
        "detalle": detalle,
        "ip": "",
    }


def al_entregar(error, mensaje):
    if error is not None:
        log.error("Kafka descartó un evento de auditoría: %s", error)


def main():
    signal.signal(signal.SIGTERM, detener)
    signal.signal(signal.SIGINT, detener)

    productor = Producer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "client.id": "db-log-shipper",
            "acks": "all",
            "enable.idempotence": True,
        }
    )

    def publicar(evento: dict) -> None:
        productor.produce(
            KAFKA_TOPIC_DB,
            key=evento.get("ip", ""),
            value=json.dumps(evento, ensure_ascii=False).encode("utf-8"),
            on_delivery=al_entregar,
        )

    posicion = leer_posicion()
    log_apagado_avisado = False
    cnx = None

    while activo:
        try:
            if cnx is None or not cnx.is_connected():
                cnx = mysql.connector.connect(**DB_CONFIG)
            if posicion is None:
                # Primer arranque: se empieza desde el final para no reenviar
                # el historial de inicialización de la base.
                posicion = consultar(cnx, "SELECT COUNT(*) FROM mysql.general_log")[0][0]
                guardar_posicion(posicion)
                log.info("Primer arranque: leyendo mysql.general_log desde la fila %d", posicion)
            desfase = timedelta(seconds=consultar(cnx, "SELECT TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(), NOW())")[0][0])
            filas = consultar(cnx, CONSULTA, (posicion, LOTE))

            alteracion = None
            if not filas:
                # Siempre debería haber filas nuevas (como mínimo, nuestra consulta
                # anterior). Si no hay, alguien vació el log o lo desactivó.
                total = consultar(cnx, "SELECT COUNT(*) FROM mysql.general_log")[0][0]
                encendido, salida = consultar(cnx, "SELECT @@GLOBAL.general_log, @@GLOBAL.log_output")[0]
                if total < posicion:
                    alteracion = ("vaciado", f"mysql.general_log tenía {posicion} filas y ahora tiene {total}")
                    posicion = 0
                elif not encendido or "TABLE" not in texto(salida).upper():
                    if not log_apagado_avisado:
                        alteracion = ("desactivado", f"general_log={encendido}, log_output={texto(salida)}")
                    log_apagado_avisado = True
            else:
                log_apagado_avisado = False
        except mysql.connector.Error as error:
            log.warning("MySQL no disponible (%s); reintentando", error)
            cnx = None
            time.sleep(5)
            continue

        enviados = 0
        if alteracion:
            log.warning("El log de auditoría de MySQL fue %s: %s", *alteracion)
            publicar(evento_log_alterado(*alteracion))
            enviados += 1
        for fila in filas:
            evento = a_evento(fila, desfase)
            if evento is not None:
                publicar(evento)
                enviados += 1
        posicion += len(filas)

        if enviados:
            pendientes = productor.flush(15)
            if pendientes:
                # Siguen en la cola del productor, que reintenta solo. La posición
                # guardada no avanza: tras un reinicio se volverían a leer.
                log.warning("Kafka aún no confirma %d eventos; se sigue reintentando", pendientes)
            else:
                guardar_posicion(posicion)
                log.info("%d eventos enviados a %s (fila %d)", enviados, KAFKA_TOPIC_DB, posicion)
        elif filas:
            guardar_posicion(posicion)

        if len(filas) < LOTE:
            time.sleep(INTERVALO_SEG)

    productor.flush(10)
    log.info("Recolector detenido")


if __name__ == "__main__":
    main()
