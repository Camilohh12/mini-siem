"""Agente de seguridad (consumidor / analizador).

Flujo por cada evento que llega de Kafka:
  1. se guarda tal cual en el almacén inmutable (bdauditoria.tbeventos);
  2. se evalúa con el motor de reglas (rules.py);
  3. cada alerta nueva se envía a Telegram y se guarda en tbalertas;
  4. solo entonces se marca el evento como procesado en Kafka.

Si el agente se cae a mitad de camino, al volver Kafka le reentrega el evento
(entrega "al menos una vez"); los duplicados se descartan por event_id.
"""

import json
import logging
import os
import signal
import time
import uuid

import mysql.connector
from confluent_kafka import Consumer, KafkaError, KafkaException
from confluent_kafka.admin import AdminClient, NewTopic

from geo import Geolocalizador
from notifier import NotificadorTelegram
from rules import Configuracion, MotorReglas, Silenciador, parsear_ts
from storage import AlmacenAuditoria

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("agente")


def lista(nombre: str, defecto: str) -> tuple:
    return tuple(v.strip() for v in os.environ.get(nombre, defecto).split(",") if v.strip())


# ── Configuración (variables de entorno) ─────────────────────────────────────
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_TOPICS = list(lista("KAFKA_TOPICS", "auth.events,db.audit"))
KAFKA_GRUPO = os.environ.get("KAFKA_GRUPO", "security-agent")
# No repetir la misma alerta (misma regla y mismo sujeto) durante este tiempo.
SILENCIO_SEG = int(os.environ.get("ALERTA_SILENCIO_SEG", "300"))

CONFIG_REGLAS = Configuracion(
    max_fallos=int(os.environ.get("MAX_FALLOS", "5")),
    ventana_fallos_seg=int(os.environ.get("VENTANA_FALLOS_SEG", "60")),
    velocidad_max_kmh=float(os.environ.get("VELOCIDAD_MAX_KMH", "900")),
    zona_horaria=os.environ.get("ZONA_HORARIA", "America/Mexico_City"),
    hora_inicio=int(os.environ.get("HORA_INUSUAL_INICIO", "0")),
    hora_fin=int(os.environ.get("HORA_INUSUAL_FIN", "6")),
    roles_admin=lista("ROLES_ADMIN", "admin"),
    max_tokens_invalidos=int(os.environ.get("MAX_TOKENS_INVALIDOS", "5")),
    usuarios_app_bd=lista("APP_DB_USERS", "app_user"),
    redes_bd_permitidas=lista("IPS_BD_PERMITIDAS", "172.28.0.20,172.28.0.21"),
    tablas_sensibles=lista("TABLAS_SENSIBLES", "tbusuarios"),
)

activo = True


def detener(*_):
    global activo
    activo = False


def validar(crudo: bytes) -> dict:
    """Comprueba que el mensaje sea un evento bien formado. Lanza ValueError si no."""
    ev = json.loads(crudo)
    if not isinstance(ev, dict):
        raise ValueError("el evento no es un objeto JSON")
    ev["event_id"] = str(uuid.UUID(str(ev.get("event_id"))))
    parsear_ts(str(ev.get("ts")))
    if not ev.get("tipo"):
        raise ValueError("falta el campo 'tipo'")
    return ev


def crear_topics():
    """Crea los topics si no existen (1 partición basta para un solo agente)."""
    admin = AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP})
    futuros = admin.create_topics(
        [NewTopic(t, num_partitions=1, replication_factor=1) for t in KAFKA_TOPICS],
        operation_timeout=20,
        request_timeout=20,
    )
    for topic, futuro in futuros.items():
        try:
            futuro.result(timeout=30)
            log.info("Topic creado: %s", topic)
        except KafkaException as error:
            if error.args[0].code() != KafkaError.TOPIC_ALREADY_EXISTS:
                log.warning("No se pudo crear el topic %s: %s", topic, error)
        except Exception as error:  # p. ej. tiempo de espera agotado
            log.warning("No se pudo crear el topic %s: %s", topic, type(error).__name__)


def guardar(operacion, descripcion: str) -> bool:
    """Ejecuta un INSERT en la base de auditoría. Si la base no responde,
    reintenta sin límite: nada se da por procesado sin haberse guardado.
    Devuelve False solo si el agente se está deteniendo."""
    espera = 1
    while activo:
        try:
            operacion()
            return True
        except (mysql.connector.errors.DataError, mysql.connector.errors.IntegrityError) as error:
            # El problema es el dato (p. ej. un campo demasiado largo), no la
            # conexión: reintentar no lo arregla, así que se registra y se sigue.
            log.error("No se pudo guardar %s: %s", descripcion, error)
            return True
        except mysql.connector.Error as error:
            log.error("Base de auditoría no disponible (%s); reintento en %s s", error, espera)
            time.sleep(espera)
            espera = min(espera * 2, 30)
    return False


def procesar(ev: dict, almacen, motor, silenciador, notificador) -> bool:
    """Guarda, analiza y alerta. Devuelve True si el evento quedó procesado."""
    if not guardar(lambda: almacen.guardar_evento(ev), f"el evento {ev['event_id']}"):
        return False
    try:
        alertas = motor.procesar(ev)
    except Exception:
        log.exception("Una regla falló con el evento %s", ev["event_id"])
        alertas = []
    for alerta in alertas:
        if not silenciador.permitir(alerta.clave):
            continue
        log.warning("ALERTA [%s] %s | %s", alerta.severidad, alerta.titulo, alerta.detalle)
        notificada = notificador.enviar(alerta)
        if not guardar(lambda: almacen.guardar_alerta(alerta, notificada), f"la alerta {alerta.regla}"):
            return False
    return True


def main():
    signal.signal(signal.SIGTERM, detener)
    signal.signal(signal.SIGINT, detener)

    almacen = AlmacenAuditoria(
        host=os.environ.get("AUDIT_DB_HOST", "audit-db"),
        port=int(os.environ.get("AUDIT_DB_PORT", "3306")),
        database=os.environ.get("AUDIT_DB_NAME", "bdauditoria"),
        user=os.environ.get("AUDIT_DB_USER", "audit_writer"),
        password=os.environ["AUDIT_DB_PASSWORD"],
    )
    notificador = NotificadorTelegram(
        os.environ.get("TELEGRAM_BOT_TOKEN", ""),
        os.environ.get("TELEGRAM_CHAT_ID", ""),
        os.environ.get("TELEGRAM_API_BASE", "https://api.telegram.org"),
    )
    geo = None
    if os.environ.get("GEOIP_HABILITADO", "true").lower() == "true":
        geo = Geolocalizador(os.environ.get("GEOIP_URL", "http://ip-api.com/json/{ip}"))
    motor = MotorReglas(CONFIG_REGLAS, geo)
    silenciador = Silenciador(SILENCIO_SEG)

    crear_topics()
    consumidor = Consumer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "group.id": KAFKA_GRUPO,
            "auto.offset.reset": "earliest",     # la primera vez, leer desde el inicio
            "enable.auto.commit": True,          # confirma periódicamente...
            "enable.auto.offset.store": False,   # ...pero solo lo que marcamos como procesado
            "topic.metadata.refresh.interval.ms": 30000,  # detectar pronto topics recién creados
        }
    )
    consumidor.subscribe(KAFKA_TOPICS)
    log.info("Agente escuchando %s en %s", KAFKA_TOPICS, KAFKA_BOOTSTRAP)

    try:
        while activo:
            msg = consumidor.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() not in (KafkaError._PARTITION_EOF, KafkaError.UNKNOWN_TOPIC_OR_PART):
                    log.error("Error de Kafka: %s", msg.error())
                continue

            try:
                ev = validar(msg.value())
            except (ValueError, TypeError) as error:
                log.error("Evento descartado (mal formado) en %s[%s]: %s", msg.topic(), msg.offset(), error)
                consumidor.store_offsets(msg)
                continue

            if procesar(ev, almacen, motor, silenciador, notificador):
                try:
                    consumidor.store_offsets(msg)
                except KafkaException as error:
                    # Pasa si Kafka reasignó la partición durante una espera larga;
                    # el evento se reentregará y se descartará por duplicado.
                    log.warning("No se pudo marcar el offset: %s", error)
    finally:
        consumidor.close()  # confirma los offsets pendientes y sale del grupo
        log.info("Agente detenido")


if __name__ == "__main__":
    main()
