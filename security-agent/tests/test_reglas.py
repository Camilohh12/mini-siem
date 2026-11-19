"""Pruebas del motor de reglas. Ejecutar desde security-agent/:  python -m pytest -q"""

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from notifier import formatear  # noqa: E402
from rules import Configuracion, MotorReglas, Silenciador, distancia_km  # noqa: E402

T0 = datetime(2026, 11, 12, 18, 0, 0, tzinfo=timezone.utc)  # 12:00 en Ciudad de México

CDMX = {"lat": 19.43, "lon": -99.13, "pais": "México", "ciudad": "Ciudad de México"}
MADRID = {"lat": 40.42, "lon": -3.70, "pais": "España", "ciudad": "Madrid"}
PUEBLA = {"lat": 19.04, "lon": -98.20, "pais": "México", "ciudad": "Puebla"}


class GeoFalso:
    def __init__(self, mapa):
        self.mapa = mapa

    def localizar(self, ip):
        return self.mapa.get(ip)


def ev(tipo, seg=0, **campos):
    return {
        "event_id": str(uuid.uuid4()),
        "ts": (T0 + timedelta(seconds=seg)).isoformat(),
        "origen": "mysql" if tipo.startswith("db_") else "auth-service",
        "tipo": tipo,
        **campos,
    }


def reglas(alertas):
    return [a.regla for a in alertas]


def motor(**kw):
    geo = GeoFalso({"1.1.1.1": CDMX, "2.2.2.2": MADRID, "3.3.3.3": PUEBLA})
    return MotorReglas(Configuracion(**kw), geo)


# ── Fuerza bruta ─────────────────────────────────────────────────────────────
def test_fuerza_bruta_salta_al_sexto_fallo_en_un_minuto():
    m = motor()
    for i in range(5):
        assert m.procesar(ev("login_failed", seg=i * 5, ip="9.9.9.9", usuario="admin")) == []
    alertas = m.procesar(ev("login_failed", seg=30, ip="9.9.9.9", usuario="admin"))
    assert reglas(alertas) == ["FUERZA_BRUTA"]
    assert "6 intentos" in alertas[0].detalle


def test_fallos_espaciados_o_de_ips_distintas_no_alertan():
    m = motor()
    for i in range(10):  # un fallo cada 20 s: nunca hay más de 5 en 60 s
        assert m.procesar(ev("login_failed", seg=i * 20, ip="9.9.9.9")) == []
    m = motor()
    for i in range(10):
        assert m.procesar(ev("login_failed", seg=i, ip=f"9.9.9.{i}")) == []


# ── Viaje imposible ──────────────────────────────────────────────────────────
def test_viaje_imposible_mexico_europa_en_10_minutos():
    m = motor()
    assert m.procesar(ev("login_success", ip="1.1.1.1", usuario="maria", rol="usuario")) == []
    alertas = m.procesar(ev("login_success", seg=600, ip="2.2.2.2", usuario="maria", rol="usuario"))
    assert reglas(alertas) == ["VIAJE_IMPOSIBLE"]
    assert "Madrid" in alertas[0].detalle and "10 min" in alertas[0].detalle


def test_viaje_posible_no_alerta():
    m = motor()
    m.procesar(ev("login_success", ip="1.1.1.1", usuario="maria"))
    # 14 horas después en Madrid: un vuelo normal
    assert m.procesar(ev("login_success", seg=14 * 3600, ip="2.2.2.2", usuario="maria")) == []
    # Ciudad cercana a los pocos minutos (cambio de red/VPN local): tampoco
    m = motor()
    m.procesar(ev("login_success", ip="1.1.1.1", usuario="maria"))
    assert m.procesar(ev("login_success", seg=60, ip="3.3.3.3", usuario="maria")) == []


def test_viaje_imposible_es_por_usuario_e_ignora_ips_sin_ubicacion():
    m = motor()
    m.procesar(ev("login_success", ip="1.1.1.1", usuario="maria"))
    assert m.procesar(ev("login_success", seg=60, ip="2.2.2.2", usuario="otro")) == []
    assert m.procesar(ev("login_success", seg=90, ip="192.168.1.5", usuario="maria")) == []


def test_distancia_cdmx_madrid():
    assert 9000 < distancia_km(CDMX["lat"], CDMX["lon"], MADRID["lat"], MADRID["lon"]) < 9200


# ── Horario inusual ──────────────────────────────────────────────────────────
def test_admin_a_las_3am_hora_local_alerta():
    m = motor()
    tres_am = 15 * 3600  # T0 (12:00 local) + 15 h = 03:00 local
    alertas = m.procesar(ev("login_success", seg=tres_am, ip="10.0.0.5", usuario="admin", rol="admin"))
    assert reglas(alertas) == ["HORARIO_INUSUAL"]
    assert "03:00" in alertas[0].detalle


def test_admin_a_mediodia_y_usuario_normal_de_madrugada_no_alertan():
    m = motor()
    assert m.procesar(ev("login_success", ip="10.0.0.5", usuario="admin", rol="admin")) == []
    assert m.procesar(ev("login_success", seg=15 * 3600, ip="10.0.0.5", usuario="maria", rol="usuario")) == []


def test_horario_que_cruza_medianoche():
    m = motor(hora_inicio=22, hora_fin=5)
    once_pm = 11 * 3600  # 23:00 local
    assert reglas(m.procesar(ev("login_success", seg=once_pm, ip="10.0.0.5", usuario="admin", rol="admin"))) == ["HORARIO_INUSUAL"]


# ── Tokens ───────────────────────────────────────────────────────────────────
def test_tokens_invalidos_repetidos():
    m = motor()
    for i in range(4):
        assert m.procesar(ev("token_invalid", seg=i, ip="9.9.9.9", motivo="InvalidSignatureError")) == []
    assert reglas(m.procesar(ev("token_invalid", seg=5, ip="9.9.9.9", motivo="InvalidSignatureError"))) == ["TOKENS_INVALIDOS"]


def test_token_usado_desde_otra_ip():
    m = motor()
    m.procesar(ev("login_success", ip="10.0.0.5", usuario="maria", jti="abc"))
    assert m.procesar(ev("token_used", seg=5, ip="10.0.0.5", usuario="maria", jti="abc")) == []
    assert reglas(m.procesar(ev("token_used", seg=9, ip="10.0.0.99", usuario="maria", jti="abc"))) == ["TOKEN_OTRA_IP"]
    # jti desconocido (p. ej. el agente se reinició): no se puede afirmar nada
    assert m.procesar(ev("token_used", seg=9, ip="10.0.0.99", jti="zzz")) == []


def test_user_agent_de_herramienta_de_ataque():
    m = motor()
    alertas = m.procesar(ev("login_failed", ip="9.9.9.9", user_agent="sqlmap/1.8#stable (https://sqlmap.org)"))
    assert reglas(alertas) == ["USER_AGENT_SOSPECHOSO"]
    assert m.procesar(ev("login_failed", ip="9.9.9.8", user_agent="Mozilla/5.0 Firefox/130")) == []


# ── Base de datos ────────────────────────────────────────────────────────────
def q(sql, usuario="app_user", ip="172.28.0.20"):
    return ev("db_query", usuario_bd=usuario, ip=ip, sentencia=sql)


def test_escalada_de_privilegios_de_la_cuenta_de_aplicacion():
    m = motor()
    for sql in ["DROP TABLE tbusuarios", "  alter table tbusuarios add c int",
                "GRANT ALL ON *.* TO 'app_user'@'%'", "/* x */ TRUNCATE tbusuarios",
                "CREATE USER 'x'@'%'", "SET  PASSWORD FOR root = 'x'"]:
        assert "ESCALADA_PRIVILEGIOS" in reglas(m.procesar(q(sql))), sql


def test_ddl_de_root_y_consultas_normales_no_son_escalada():
    m = motor()
    assert m.procesar(q("ALTER TABLE tbusuarios ADD c INT", usuario="root")) == []
    assert m.procesar(q("SELECT id, usuario, password_hash, rol, activo FROM tbusuarios WHERE usuario = 'maria' LIMIT 1")) == []
    assert m.procesar(q("SELECT dropped, created FROM tbusuarios WHERE id = 1")) == []


def test_extraccion_masiva():
    m = motor()
    for sql in ["SELECT * FROM tbusuarios", "select usuario, password_hash from bddatos.tbusuarios",
                "SELECT * FROM `bddatos`.`tbusuarios` ORDER BY id",
                "SELECT /*!40001 SQL_NO_CACHE */ * FROM `tbusuarios`",
                "SELECT * FROM tbusuarios WHERE 1=1 INTO OUTFILE '/tmp/x.csv'"]:
        assert "EXTRACCION_MASIVA" in reglas(m.procesar(q(sql, usuario="root"))), sql


def test_lecturas_acotadas_no_son_extraccion():
    m = motor()
    for sql in ["SELECT * FROM tbusuarios WHERE id = 7", "SELECT * FROM tbusuarios LIMIT 10",
                "SELECT COUNT(*) FROM tbusuarios", "SELECT * FROM otra_tabla",
                "SELECT * FROM tbusuarios_log", "SELECT 1"]:
        assert m.procesar(q(sql, usuario="root")) == [], sql


def test_conexion_directa_desde_ip_no_autorizada():
    m = motor()
    c = lambda ip, **k: ev("db_connect", usuario_bd="root", ip=ip, **k)  # noqa: E731
    assert m.procesar(c("172.28.0.20")) == []          # auth-service
    assert m.procesar(c("")) == []                     # socket local
    alertas = m.procesar(c("172.28.0.1"))
    assert reglas(alertas) == ["CONEXION_DIRECTA"] and "ACEPTADA" in alertas[0].detalle
    alertas = m.procesar(c("203.0.113.7", acceso_denegado=True))
    assert "RECHAZADA" in alertas[0].detalle


def test_log_de_auditoria_vaciado_es_alerta_critica():
    alertas = motor().procesar(ev("db_log_alterado", motivo="vaciado", detalle="tenía 900 filas y ahora 0"))
    assert reglas(alertas) == ["LOG_AUDITORIA_ALTERADO"] and alertas[0].severidad == "CRITICA"


# ── Silenciador y formato de Telegram ────────────────────────────────────────
def test_silenciador_no_repite_la_misma_alerta():
    s = Silenciador(300)
    assert s.permitir("FUERZA_BRUTA:9.9.9.9", ahora=0)
    assert not s.permitir("FUERZA_BRUTA:9.9.9.9", ahora=100)
    assert s.permitir("FUERZA_BRUTA:8.8.8.8", ahora=100)
    assert s.permitir("FUERZA_BRUTA:9.9.9.9", ahora=301)


def test_mensaje_de_telegram_escapa_html():
    m = motor()
    alerta = m.procesar(ev("login_failed", ip="9.9.9.9", user_agent="<b>sqlmap</b>&"))[0]
    texto = formatear(alerta)
    assert "&lt;b&gt;sqlmap&lt;/b&gt;&amp;" in texto and "<b>sqlmap" not in texto
    assert texto.startswith("🟠 <b>[MEDIA]")
