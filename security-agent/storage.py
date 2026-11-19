"""Almacenamiento inmutable de auditoría.

El agente se conecta a una base de datos separada (bdauditoria) con una
cuenta que solo tiene privilegio INSERT: puede añadir registros, pero no
leerlos, modificarlos ni borrarlos.
"""

import json
import logging

import mysql.connector
from mysql.connector import errorcode

from rules import parsear_ts

log = logging.getLogger("almacen")


class AlmacenAuditoria:
    def __init__(self, host: str, port: int, database: str, user: str, password: str):
        self._config = dict(
            host=host, port=port, database=database, user=user, password=password,
            connection_timeout=5, autocommit=True,
        )
        self._cnx = None

    def _conexion(self):
        if self._cnx is None or not self._cnx.is_connected():
            self._cnx = mysql.connector.connect(**self._config)
        return self._cnx

    def _insertar(self, sql: str, valores: tuple) -> None:
        """Ejecuta un INSERT. Un duplicado (evento reentregado por Kafka) se ignora;
        cualquier otro error se propaga para que el agente reintente."""
        try:
            cursor = self._conexion().cursor()
            cursor.execute(sql, valores)
            cursor.close()
        except mysql.connector.Error as error:
            if error.errno == errorcode.ER_DUP_ENTRY:
                return
            self._cnx = None  # fuerza reconexión en el siguiente intento
            raise

    def guardar_evento(self, ev: dict) -> None:
        self._insertar(
            "INSERT INTO tbeventos (event_id, ocurrido_en, origen, tipo, usuario, ip, payload) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                ev["event_id"],
                parsear_ts(ev["ts"]).replace(tzinfo=None),
                str(ev.get("origen", ""))[:40],
                str(ev.get("tipo", ""))[:40],
                _texto(ev.get("usuario") or ev.get("usuario_bd"), 100),
                _texto(ev.get("ip"), 45),
                json.dumps(ev, ensure_ascii=False),
            ),
        )

    def guardar_alerta(self, alerta, notificada: bool) -> None:
        self._insertar(
            "INSERT INTO tbalertas (alerta_id, regla, severidad, titulo, detalle, clave, event_id, notificada) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                alerta.alerta_id, alerta.regla, alerta.severidad, alerta.titulo[:200],
                alerta.detalle, alerta.clave[:200], alerta.evento.get("event_id"), int(notificada),
            ),
        )


def _texto(valor, largo: int) -> str | None:
    """Recorta a la longitud de la columna; vacío -> NULL."""
    return str(valor)[:largo] if valor else None
