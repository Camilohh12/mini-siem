"""Microservicio de autenticación (productor de eventos de auditoría).

Endpoints:
  POST /login   {"usuario": "...", "password": "..."}  -> JWT
  GET  /perfil  (Authorization: Bearer <token>)        -> datos del token
  GET  /health

Eventos que publica en Kafka (topic auth.events):
  login_success, login_failed, token_used, token_invalid
"""

import ipaddress
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import mysql.connector
from fastapi import FastAPI, HTTPException, Request
from mysql.connector import pooling
from pydantic import BaseModel, Field

from audit import EmisorAuditoria

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("auth")

# ── Configuración ────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "mysql"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "database": os.environ.get("DB_NAME", "bddatos"),
    "user": os.environ["DB_USER"],
    "password": os.environ["DB_PASSWORD"],
    "connection_timeout": 5,
}
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITMO = "HS256"
JWT_MINUTOS = int(os.environ.get("JWT_MINUTOS", "30"))
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_TOPIC_AUTH = os.environ.get("KAFKA_TOPIC_AUTH", "auth.events")
TRUST_PROXY = os.environ.get("TRUST_PROXY", "false").lower() == "true"

if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET debe tener al menos 32 caracteres")

# Hash de relleno: si el usuario no existe se verifica contra este hash para
# que la respuesta tarde lo mismo y no revele qué usuarios existen.
HASH_SENUELO = b"$2b$12$neTny/mcBQP8/It0Nsi7vOR3Pv9UWZMEyQ0hM9JSILixCBbTO1tdy"

_pool: pooling.MySQLConnectionPool | None = None
auditoria: EmisorAuditoria | None = None


@asynccontextmanager
async def ciclo_de_vida(app: FastAPI):
    global auditoria
    auditoria = EmisorAuditoria(KAFKA_BOOTSTRAP, KAFKA_TOPIC_AUTH, origen="auth-service")
    yield
    auditoria.cerrar()


app = FastAPI(title="Auth Service", lifespan=ciclo_de_vida)


class Credenciales(BaseModel):
    usuario: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=128)


# ── Utilidades ───────────────────────────────────────────────────────────────
def conexion_bd():
    """Devuelve una conexión del pool (se crea en el primer uso)."""
    global _pool
    if _pool is None:
        _pool = pooling.MySQLConnectionPool(pool_name="auth", pool_size=5, **DB_CONFIG)
    return _pool.get_connection()


def buscar_usuario(usuario: str) -> dict | None:
    cnx = conexion_bd()
    try:
        cursor = cnx.cursor(dictionary=True)
        # Consulta parametrizada: el valor nunca se concatena al SQL.
        cursor.execute(
            "SELECT id, usuario, password_hash, rol, activo "
            "FROM tbusuarios WHERE usuario = %s LIMIT 1",
            (usuario,),
        )
        fila = cursor.fetchone()
        cursor.close()
        return fila
    finally:
        cnx.close()  # la devuelve al pool


def ip_cliente(request: Request) -> str:
    """IP de origen. X-Forwarded-For solo se respeta si TRUST_PROXY=true,
    porque cualquier cliente puede inventar esa cabecera."""
    if TRUST_PROXY:
        reenviada = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        try:
            return str(ipaddress.ip_address(reenviada))
        except ValueError:
            pass
    return request.client.host if request.client else "desconocida"


def contexto(request: Request) -> dict:
    """Datos del cliente que acompañan a todo evento de auditoría."""
    return {
        "ip": ip_cliente(request),
        "user_agent": request.headers.get("user-agent", "")[:300],
    }


# ── Endpoints ────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(datos: Credenciales, request: Request):
    ctx = contexto(request)

    try:
        fila = buscar_usuario(datos.usuario)
    except mysql.connector.Error:
        log.exception("Error consultando la base de datos")
        raise HTTPException(status_code=503, detail="Servicio no disponible")

    # Siempre se calcula bcrypt, exista o no el usuario.
    clave = datos.password.encode("utf-8")
    hash_guardado = fila["password_hash"].encode() if fila else HASH_SENUELO
    coincide = len(clave) <= 72 and bcrypt.checkpw(clave, hash_guardado)

    motivo = None
    if fila is None:
        motivo = "usuario_inexistente"
    elif not coincide:
        motivo = "password_incorrecto"
    elif not fila["activo"]:
        motivo = "usuario_inactivo"

    if motivo:
        # ── LOG DE AUDITORÍA: intento fallido ──
        auditoria.emitir("login_failed", usuario=datos.usuario, motivo=motivo, **ctx)
        # Mismo mensaje para todos los casos: no se le dan pistas al atacante.
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    ahora = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())  # identificador único del token
    token = jwt.encode(
        {
            "sub": str(fila["id"]),
            "usuario": fila["usuario"],
            "rol": fila["rol"],
            "jti": jti,
            "iat": ahora,
            "exp": ahora + timedelta(minutes=JWT_MINUTOS),
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITMO,
    )

    # ── LOG DE AUDITORÍA: acceso exitoso (se registra el jti, nunca el token) ──
    auditoria.emitir(
        "login_success",
        usuario=fila["usuario"],
        usuario_id=fila["id"],
        rol=fila["rol"],
        jti=jti,
        **ctx,
    )
    return {"access_token": token, "token_type": "bearer", "expires_in": JWT_MINUTOS * 60}


@app.get("/perfil")
def perfil(request: Request):
    """Ejemplo de endpoint protegido: también audita el uso de tokens."""
    ctx = contexto(request)
    esquema, _, token = request.headers.get("authorization", "").partition(" ")
    if esquema.lower() != "bearer" or not token:
        auditoria.emitir("token_invalid", motivo="sin_token", **ctx)
        raise HTTPException(status_code=401, detail="Token requerido")

    try:
        datos = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITMO],
            options={"require": ["exp", "jti", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        auditoria.emitir("token_invalid", motivo="expirado", **ctx)
        raise HTTPException(status_code=401, detail="Token inválido")
    except jwt.InvalidTokenError as error:
        # Firma incorrecta, token manipulado o mal formado.
        auditoria.emitir("token_invalid", motivo=type(error).__name__, **ctx)
        raise HTTPException(status_code=401, detail="Token inválido")

    auditoria.emitir(
        "token_used",
        usuario=datos["usuario"],
        rol=datos["rol"],
        jti=datos["jti"],
        ruta=request.url.path,
        **ctx,
    )
    return {"id": int(datos["sub"]), "usuario": datos["usuario"], "rol": datos["rol"]}
