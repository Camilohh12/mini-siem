"""Emisión de eventos de auditoría hacia Kafka (lado productor).

Cada intento de acceso se convierte en un evento JSON y se publica de forma
asíncrona: el login nunca espera a Kafka ni falla si Kafka está caído.
Como respaldo, el mismo evento se escribe en stdout (visible con `docker logs`).
"""

import json
import logging
import uuid
from datetime import datetime, timezone

from confluent_kafka import KafkaException, Producer

log = logging.getLogger("auditoria")


class EmisorAuditoria:
    def __init__(self, bootstrap: str, topic: str, origen: str):
        self._topic = topic
        self._origen = origen
        self._productor = Producer(
            {
                "bootstrap.servers": bootstrap,
                "client.id": origen,
                "acks": "all",                 # el broker confirma que lo guardó
                "enable.idempotence": True,    # sin duplicados por reintentos
                "linger.ms": 50,               # agrupa eventos durante 50 ms
                "message.timeout.ms": 120000,  # reintenta hasta 2 min si Kafka no responde
            }
        )

    def emitir(self, tipo: str, **campos) -> dict:
        """Publica un evento. Nunca incluyas contraseñas ni tokens completos."""
        evento = {
            "event_id": str(uuid.uuid4()),
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "origen": self._origen,
            "tipo": tipo,
            **campos,
        }
        linea = json.dumps(evento, ensure_ascii=False)
        log.info(linea)  # respaldo local
        try:
            self._productor.produce(
                self._topic,
                # Misma clave -> misma partición -> Kafka conserva el orden de los
                # eventos de un mismo usuario (necesario para reglas como "token
                # usado desde otra IP" si el topic tuviera varias particiones).
                key=str(campos.get("usuario") or campos.get("ip") or ""),
                value=linea.encode("utf-8"),
                on_delivery=self._al_entregar,
            )
            self._productor.poll(0)  # atiende confirmaciones pendientes, sin bloquear
        except (BufferError, KafkaException) as error:
            log.error("No se pudo encolar el evento %s: %s", evento["event_id"], error)
        return evento

    @staticmethod
    def _al_entregar(error, mensaje):
        if error is not None:
            log.error("Kafka no confirmó un evento de auditoría: %s", error)

    def cerrar(self):
        """Envía lo que quede en cola antes de apagar el servicio."""
        self._productor.flush(10)
