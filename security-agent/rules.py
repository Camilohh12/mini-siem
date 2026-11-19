"""Motor de reglas de detección.

Recibe eventos (dict) uno por uno y devuelve una lista de alertas.
No hace E/S (salvo la geolocalización, que se inyecta), así que se puede
probar sin Kafka ni base de datos: ver tests/test_reglas.py.

Reglas implementadas
  Auth:  FUERZA_BRUTA, VIAJE_IMPOSIBLE, HORARIO_INUSUAL,
         TOKENS_INVALIDOS, TOKEN_OTRA_IP, USER_AGENT_SOSPECHOSO
  BD:    ESCALADA_PRIVILEGIOS, EXTRACCION_MASIVA, CONEXION_DIRECTA,
         LOG_AUDITORIA_ALTERADO
"""

import ipaddress
import math
import re
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo


@dataclass
class Configuracion:
    # Fuerza bruta: MÁS de `max_fallos` intentos fallidos desde una IP en la ventana.
    max_fallos: int = 5
    ventana_fallos_seg: int = 60
    # Viaje imposible: dos logins del mismo usuario que exigirían viajar más rápido
    # que un avión comercial.
    velocidad_max_kmh: float = 900.0
    distancia_min_km: float = 500.0
    # Horario inusual: accesos de administradores entre hora_inicio y hora_fin (hora local).
    zona_horaria: str = "America/Mexico_City"
    hora_inicio: int = 0
    hora_fin: int = 6
    roles_admin: tuple = ("admin",)
    # Tokens JWT
    max_tokens_invalidos: int = 5
    ventana_tokens_seg: int = 60
    duracion_sesion_min: int = 60
    user_agents_sospechosos: tuple = ("sqlmap", "hydra", "nikto", "nmap", "masscan", "gobuster", "wfuzz")
    # Base de datos
    usuarios_app_bd: tuple = ("app_user",)
    redes_bd_permitidas: tuple = ("172.28.0.20/32", "172.28.0.21/32")
    tablas_sensibles: tuple = ("tbusuarios",)


@dataclass
class Alerta:
    regla: str
    severidad: str            # CRITICA | ALTA | MEDIA
    titulo: str
    detalle: str
    clave: str                # identifica al "sujeto" (para no repetir la misma alerta)
    evento: dict
    alerta_id: str = field(default_factory=lambda: str(uuid.uuid4()))


class Silenciador:
    """Evita inundar Telegram: una alerta con la misma clave no se repite
    hasta que pasen `segundos`."""

    def __init__(self, segundos: int):
        self._segundos = segundos
        self._ultima: dict[str, float] = {}

    def permitir(self, clave: str, ahora: float | None = None) -> bool:
        ahora = time.monotonic() if ahora is None else ahora
        previa = self._ultima.get(clave)
        if previa is not None and ahora - previa < self._segundos:
            return False
        if len(self._ultima) > 10000:
            self._ultima = {c: t for c, t in self._ultima.items() if ahora - t < self._segundos}
        self._ultima[clave] = ahora
        return True


def parsear_ts(valor: str) -> datetime:
    """Convierte la marca de tiempo ISO-8601 del evento a datetime en UTC."""
    ts = datetime.fromisoformat(valor)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def distancia_km(lat1, lon1, lat2, lon2) -> float:
    """Distancia sobre la superficie terrestre (fórmula de Haversine)."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


# Sentencias que una cuenta de aplicación nunca debería ejecutar (DDL / DCL).
RE_DDL_DCL = re.compile(
    r"^\s*(?:/\*.*?\*/\s*)*(DROP|ALTER|GRANT|REVOKE|TRUNCATE|CREATE|RENAME|SET\s+PASSWORD)\b",
    re.IGNORECASE | re.DOTALL,
)
RE_SELECT = re.compile(r"^\s*(?:/\*.*?\*/\s*)*SELECT\b", re.IGNORECASE | re.DOTALL)
RE_SOLO_CONTEO = re.compile(r"^\s*SELECT\s+COUNT\s*\(", re.IGNORECASE)
RE_WHERE_O_LIMIT = re.compile(r"\b(WHERE|LIMIT)\b", re.IGNORECASE)
RE_VOLCADO = re.compile(r"\bINTO\s+(OUTFILE|DUMPFILE)\b|SQL_NO_CACHE", re.IGNORECASE)


class MotorReglas:
    def __init__(self, config: Configuracion | None = None, geolocalizador=None):
        self.cfg = config or Configuracion()
        self.geo = geolocalizador
        self._zona = ZoneInfo(self.cfg.zona_horaria)
        self._redes = [ipaddress.ip_network(r, strict=False) for r in self.cfg.redes_bd_permitidas]
        self._re_tablas = [
            re.compile(rf"\b(?:FROM|JOIN)\s+(?:`?\w+`?\.)?`?{re.escape(t)}`?(?!\w)", re.IGNORECASE)
            for t in self.cfg.tablas_sensibles
        ]
        # Estado en memoria (ventanas deslizantes).
        self._fallos = defaultdict(deque)            # ip -> marcas de tiempo de fallos
        self._tokens_invalidos = defaultdict(deque)  # ip -> marcas de tiempo
        self._ultimo_login = {}                      # usuario -> (ts, ubicación, ip)
        self._sesiones = {}                          # jti -> (ip, usuario, ts)
        self._procesados = 0

    # ── Punto de entrada ────────────────────────────────────────────────────
    def procesar(self, ev: dict) -> list[Alerta]:
        ts = parsear_ts(ev["ts"])
        tipo = ev.get("tipo")
        manejador = {
            "login_failed": self._login_fallido,
            "login_success": self._login_exitoso,
            "token_invalid": self._token_invalido,
            "token_used": self._token_usado,
            "db_connect": self._conexion_bd,
            "db_query": self._consulta_bd,
            "db_log_alterado": self._log_alterado,
        }.get(tipo)

        alertas = []
        if manejador:
            alertas += manejador(ev, ts)
        if ev.get("origen") != "mysql":
            alertas += self._user_agent(ev)

        self._procesados += 1
        if self._procesados % 1000 == 0:
            self._limpiar(ts)
        return alertas

    # ── Reglas de autenticación ─────────────────────────────────────────────
    def _login_fallido(self, ev, ts):
        ip = ev.get("ip", "")
        n = self._contar(self._fallos[ip], ts, self.cfg.ventana_fallos_seg)
        if n > self.cfg.max_fallos:
            return [Alerta(
                "FUERZA_BRUTA", "ALTA", "Posible ataque de fuerza bruta",
                f"{n} intentos de login fallidos desde la IP {ip} en "
                f"{self.cfg.ventana_fallos_seg} s. Último usuario probado: {ev.get('usuario', '?')}.",
                clave=f"FUERZA_BRUTA:{ip}", evento=ev,
            )]
        return []

    def _login_exitoso(self, ev, ts):
        alertas = []
        usuario, ip = ev.get("usuario", ""), ev.get("ip", "")
        if ev.get("jti"):
            self._sesiones[ev["jti"]] = (ip, usuario, ts)

        # Horario inusual para administradores
        hora_local = ts.astimezone(self._zona)
        if ev.get("rol") in self.cfg.roles_admin and self._en_horario_inusual(hora_local.hour):
            alertas.append(Alerta(
                "HORARIO_INUSUAL", "MEDIA", "Acceso administrativo en horario inusual",
                f"El administrador '{usuario}' inició sesión a las {hora_local:%H:%M} "
                f"({self.cfg.zona_horaria}) desde la IP {ip}.",
                clave=f"HORARIO_INUSUAL:{usuario}:{hora_local:%Y-%m-%d}", evento=ev,
            ))

        # Viaje imposible
        ubicacion = self.geo.localizar(ip) if self.geo else None
        if ubicacion:
            previo = self._ultimo_login.get(usuario)
            if previo:
                ts_prev, ubi_prev, ip_prev = previo
                km = distancia_km(ubi_prev["lat"], ubi_prev["lon"], ubicacion["lat"], ubicacion["lon"])
                horas = max((ts - ts_prev).total_seconds(), 1) / 3600
                if km >= self.cfg.distancia_min_km and km / horas > self.cfg.velocidad_max_kmh:
                    minutos = (ts - ts_prev).total_seconds() / 60
                    alertas.append(Alerta(
                        "VIAJE_IMPOSIBLE", "ALTA", "Viaje imposible",
                        f"'{usuario}' inició sesión desde {_lugar(ubi_prev)} (IP {ip_prev}) y "
                        f"{minutos:.0f} min después desde {_lugar(ubicacion)} (IP {ip}): "
                        f"{km:,.0f} km de distancia.",
                        clave=f"VIAJE_IMPOSIBLE:{usuario}", evento=ev,
                    ))
            self._ultimo_login[usuario] = (ts, ubicacion, ip)
        return alertas

    def _token_invalido(self, ev, ts):
        ip = ev.get("ip", "")
        n = self._contar(self._tokens_invalidos[ip], ts, self.cfg.ventana_tokens_seg)
        if n >= self.cfg.max_tokens_invalidos:
            return [Alerta(
                "TOKENS_INVALIDOS", "ALTA", "Tokens JWT inválidos repetidos",
                f"{n} peticiones con token inválido desde la IP {ip} en "
                f"{self.cfg.ventana_tokens_seg} s (último motivo: {ev.get('motivo', '?')}). "
                "Puede ser un intento de falsificar o adivinar tokens.",
                clave=f"TOKENS_INVALIDOS:{ip}", evento=ev,
            )]
        return []

    def _token_usado(self, ev, ts):
        sesion = self._sesiones.get(ev.get("jti"))
        ip = ev.get("ip", "")
        if sesion and sesion[0] != ip:
            return [Alerta(
                "TOKEN_OTRA_IP", "ALTA", "Token usado desde otra IP",
                f"El token de '{sesion[1]}' se emitió para la IP {sesion[0]} y ahora se usa "
                f"desde {ip}. Posible robo de sesión.",
                clave=f"TOKEN_OTRA_IP:{ev.get('jti')}:{ip}", evento=ev,
            )]
        return []

    def _user_agent(self, ev):
        ua = (ev.get("user_agent") or "").lower()
        for firma in self.cfg.user_agents_sospechosos:
            if firma in ua:
                return [Alerta(
                    "USER_AGENT_SOSPECHOSO", "MEDIA", "Herramienta de ataque detectada",
                    f"Petición desde la IP {ev.get('ip', '?')} con User-Agent "
                    f"'{ev.get('user_agent', '')[:120]}' (coincide con '{firma}').",
                    clave=f"USER_AGENT_SOSPECHOSO:{ev.get('ip', '')}:{firma}", evento=ev,
                )]
        return []

    # ── Reglas de base de datos ─────────────────────────────────────────────
    def _conexion_bd(self, ev, ts):
        ip = ev.get("ip", "")
        if not ip:  # conexión local por socket (dentro del propio servidor)
            return []
        try:
            direccion = ipaddress.ip_address(ip)
        except ValueError:
            return []
        if any(direccion in red for red in self._redes):
            return []
        resultado = "RECHAZADA por credenciales" if ev.get("acceso_denegado") else "ACEPTADA"
        return [Alerta(
            "CONEXION_DIRECTA", "ALTA", "Conexión directa a la base de datos",
            f"Conexión {resultado} como '{ev.get('usuario_bd', '?')}' desde {ip}, "
            "una IP que no pertenece a los microservicios autorizados.",
            clave=f"CONEXION_DIRECTA:{ip}:{ev.get('usuario_bd', '')}", evento=ev,
        )]

    def _consulta_bd(self, ev, ts):
        alertas = []
        sql = ev.get("sentencia", "")
        usuario = ev.get("usuario_bd", "")
        resumen = " ".join(sql.split())[:200]

        m = RE_DDL_DCL.match(sql)
        if m and usuario in self.cfg.usuarios_app_bd:
            comando = " ".join(m.group(1).upper().split())
            alertas.append(Alerta(
                "ESCALADA_PRIVILEGIOS", "CRITICA", "Posible escalada de privilegios en la BD",
                f"La cuenta de aplicación '{usuario}' ejecutó {comando} desde "
                f"{ev.get('ip') or 'socket local'}: {resumen}",
                clave=f"ESCALADA_PRIVILEGIOS:{usuario}:{comando}", evento=ev,
            ))

        if RE_SELECT.match(sql) and not RE_SOLO_CONTEO.match(sql):
            tabla = next((t for t, r in zip(self.cfg.tablas_sensibles, self._re_tablas) if r.search(sql)), None)
            sin_filtro = not RE_WHERE_O_LIMIT.search(sql)
            if tabla and (sin_filtro or RE_VOLCADO.search(sql)):
                alertas.append(Alerta(
                    "EXTRACCION_MASIVA", "ALTA", "Posible extracción masiva de datos",
                    f"'{usuario}' leyó la tabla sensible '{tabla}' completa (SELECT sin WHERE ni "
                    f"LIMIT, o volcado a archivo) desde {ev.get('ip') or 'socket local'}: {resumen}",
                    clave=f"EXTRACCION_MASIVA:{usuario}:{tabla}", evento=ev,
                ))
        return alertas

    def _log_alterado(self, ev, ts):
        return [Alerta(
            "LOG_AUDITORIA_ALTERADO", "CRITICA", "El log de auditoría de MySQL fue alterado",
            f"El log general de MySQL fue {ev.get('motivo', 'modificado')} ({ev.get('detalle', '')}). "
            "Alguien podría estar intentando borrar sus huellas.",
            clave=f"LOG_AUDITORIA_ALTERADO:{ev.get('motivo', '')}", evento=ev,
        )]

    # ── Auxiliares ──────────────────────────────────────────────────────────
    @staticmethod
    def _contar(ventana: deque, ts: datetime, segundos: int) -> int:
        """Agrega `ts` a la ventana deslizante y devuelve cuántos eventos quedan en ella."""
        ventana.append(ts)
        limite = ts - timedelta(seconds=segundos)
        while ventana and ventana[0] < limite:
            ventana.popleft()
        return len(ventana)

    def _en_horario_inusual(self, hora: int) -> bool:
        ini, fin = self.cfg.hora_inicio, self.cfg.hora_fin
        return ini <= hora < fin if ini <= fin else (hora >= ini or hora < fin)

    def _limpiar(self, ahora: datetime) -> None:
        """Evita que el estado en memoria crezca sin límite."""
        limite = ahora - timedelta(minutes=self.cfg.duracion_sesion_min)
        self._sesiones = {j: s for j, s in self._sesiones.items() if s[2] >= limite}
        for ventanas in (self._fallos, self._tokens_invalidos):
            for ip in [ip for ip, v in ventanas.items() if not v or v[-1] < limite]:
                del ventanas[ip]


def _lugar(ubicacion: dict) -> str:
    return ", ".join(p for p in (ubicacion.get("ciudad"), ubicacion.get("pais")) if p) or "ubicación desconocida"
