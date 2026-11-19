"""Notificaciones por Telegram (Bot API, método sendMessage).

Necesita dos datos, ambos en variables de entorno (nunca en el código):
  TELEGRAM_BOT_TOKEN  el token que te dio @BotFather
  TELEGRAM_CHAT_ID    el chat (o grupo) que recibirá las alertas
"""

import html
import logging
import time

import requests

log = logging.getLogger("telegram")

ICONOS = {"CRITICA": "🚨", "ALTA": "🔴", "MEDIA": "🟠"}


def formatear(alerta) -> str:
    """Texto de la alerta en HTML de Telegram (los datos del evento se escapan)."""
    ev = alerta.evento
    lineas = [
        f"{ICONOS.get(alerta.severidad, '⚠️')} <b>[{alerta.severidad}] {html.escape(alerta.titulo, quote=False)}</b>",
        "",
        html.escape(alerta.detalle, quote=False),
        "",
        f"<b>Regla:</b> {alerta.regla}",
        f"<b>Origen:</b> {html.escape(str(ev.get('origen', '?')))}",
        f"<b>Hora (UTC):</b> {html.escape(str(ev.get('ts', '?')))}",
        f"<b>Evento:</b> <code>{html.escape(str(ev.get('event_id', '?')))}</code>",
    ]
    return "\n".join(lineas)[:4000]  # Telegram admite hasta 4096 caracteres


class NotificadorTelegram:
    def __init__(self, token: str, chat_id: str, api_base: str = "https://api.telegram.org"):
        self._token = token
        self._chat_id = chat_id
        self._url = f"{api_base.rstrip('/')}/bot{token}/sendMessage"
        self.habilitado = bool(token and chat_id)
        if not self.habilitado:
            log.warning("Telegram sin configurar: las alertas solo se verán en el log y en la BD")

    def enviar(self, alerta) -> bool:
        """Envía la alerta. Devuelve True si Telegram la aceptó."""
        if not self.habilitado:
            return False
        cuerpo = {
            "chat_id": self._chat_id,
            "text": formatear(alerta),
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        for intento in range(3):
            try:
                r = requests.post(self._url, json=cuerpo, timeout=10)
            except requests.RequestException as error:
                # Ojo: el mensaje de la excepción contiene la URL con el token; no se registra.
                log.warning("Telegram no responde (%s), intento %d/3", type(error).__name__, intento + 1)
                time.sleep(2 * (intento + 1))
                continue

            if r.status_code == 200:
                return True
            if r.status_code == 429:  # demasiados mensajes: Telegram indica cuánto esperar
                espera = min(self._retry_after(r), 30)
                log.warning("Telegram pide esperar %s s", espera)
                time.sleep(espera)
                continue
            # 400 = chat_id incorrecto o mensaje mal formado; 401 = token inválido; 403 = bot bloqueado
            log.error("Telegram rechazó la alerta: HTTP %s %s", r.status_code, self._descripcion(r))
            return False
        return False

    @staticmethod
    def _retry_after(respuesta) -> int:
        try:
            return int(respuesta.json()["parameters"]["retry_after"])
        except (ValueError, KeyError, TypeError):
            return 5

    @staticmethod
    def _descripcion(respuesta) -> str:
        try:
            return str(respuesta.json().get("description", ""))[:200]
        except ValueError:
            return ""
