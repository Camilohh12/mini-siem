# Mini-SIEM: agente de auditoría y detección de anomalías

Monitoreo de seguridad para microservicios con enfoque asíncrono basado en eventos.

```
 PRODUCTORES                    CANAL            CONSUMIDOR                 DESTINOS
 auth-service (login) ───────┐                                          ┌─► Telegram (alertas)
                             ├─► Kafka ───► security-agent (reglas) ────┤
 mysql ─► db-log-shipper ────┘   auth.events                            └─► audit-db (solo INSERT)
 (general_log)                   db.audit                                    tbeventos, tbalertas
```

| Contenedor | Qué hace |
|---|---|
| `siem-mysql` | MySQL 8.4 con la base `bddatos` y la tabla `tbusuarios`. Registra cada conexión y sentencia en `mysql.general_log`. |
| `siem-kafka` | Canal centralizado de eventos (Kafka en modo KRaft, sin ZooKeeper). |
| `siem-auth` | Microservicio de login (FastAPI). Publica cada intento de acceso en `auth.events`. |
| `siem-db-shipper` | Lee el log de MySQL y lo publica en `db.audit`. |
| `siem-agent` | El agente: consume ambos topics, aplica las reglas, avisa por Telegram. |
| `siem-audit-db` | MySQL separado, sin puertos expuestos y en una red interna. El agente solo puede insertar. |

---

## 1. Guía rápida: MySQL con Docker

**Lanzarlo suelto** (para recordar la forma básica, sin el resto del proyecto):

```bash
docker run -d --name mysql-bddatos \
  -e MYSQL_ROOT_PASSWORD=MiClaveRoot \
  -e MYSQL_DATABASE=bddatos \
  -p 127.0.0.1:3306:3306 \
  -v mysql_data:/var/lib/mysql \
  mysql:8.4
```

- `MYSQL_DATABASE` crea la base al primer arranque.
- `-v mysql_data:/var/lib/mysql` guarda los datos en un volumen; sin él se pierden al borrar el contenedor.
- Cualquier `.sql` o `.sh` montado en `/docker-entrypoint-initdb.d/` se ejecuta **una sola vez**, cuando el volumen está vacío. Así se crea `tbusuarios` en este proyecto (`mysql/init/`).

**En este proyecto** MySQL se lanza con Compose (sección 2). Comandos del día a día:

```bash
docker compose ps                          # estado de los contenedores
docker compose logs -f mysql               # ver el log de arranque
docker exec -it siem-mysql mysql -uroot -p # entrar a la consola (pide MYSQL_ROOT_PASSWORD)
docker compose stop / start                # apagar / encender sin perder datos
docker compose down                        # borrar contenedores (los datos siguen en los volúmenes)
docker compose down -v                     # borrar TODO, incluidos los datos (reinicio limpio)
```

Dentro de la consola de MySQL:

```sql
SHOW DATABASES;
USE bddatos;
SHOW TABLES;
DESCRIBE tbusuarios;
SELECT id, usuario, email, rol, activo FROM tbusuarios;
```

**Agregar un usuario.** Las contraseñas se guardan como hash bcrypt. Genera el hash y luego insértalo como root:

```bash
docker exec siem-auth python -c "import bcrypt; print(bcrypt.hashpw(b'MiClave123', bcrypt.gensalt()).decode())"
```
```sql
INSERT INTO bddatos.tbusuarios (usuario, email, password_hash, rol)
VALUES ('camilo', 'camilo@ejemplo.com', '<hash generado>', 'usuario');
```

**Respaldo:** `docker exec -e MYSQL_PWD=<clave root> siem-mysql mysqldump -uroot bddatos > respaldo.sql`
(el agente lo reportará como extracción masiva: es justo lo que hace un volcado).

---

## 2. Puesta en marcha del proyecto completo

Requisitos: Docker Desktop (o Docker Engine + Compose v2) y unos 3 GB de RAM libres.

```bash
cp .env.example .env        # 1) crea tu archivo de configuración
#                             2) edita .env: cambia las contraseñas y pon los datos de Telegram
docker compose up -d --build   # 3) construye y levanta todo (la primera vez tarda unos minutos)
docker compose ps              # 4) todos deben quedar "running" / "healthy"
docker compose logs -f security-agent   # 5) debe decir "Agente escuchando [...]"
```

### Telegram

En `.env`:

- `TELEGRAM_BOT_TOKEN`: el token (API key) de tu bot.
- `TELEGRAM_CHAT_ID`: el chat que recibirá las alertas. Para obtenerlo, escríbele cualquier mensaje a tu bot
  y abre en el navegador `https://api.telegram.org/bot<TU_TOKEN>/getUpdates`; busca `"chat":{"id": ...}`.
  Para un grupo, agrega el bot al grupo, escribe algo y usa el id (negativo) que aparezca.

Prueba rápida del token y el chat:

```bash
curl -s "https://api.telegram.org/bot<TU_TOKEN>/sendMessage" -d chat_id=<TU_CHAT_ID> -d text="Hola desde el SIEM"
```

Después de cambiar `.env`: `docker compose up -d` (recrea los contenedores afectados).
Si Telegram queda sin configurar, el agente sigue funcionando y las alertas quedan en su log y en `tbalertas`.

---

## 3. Probar que funciona

Login (usuarios de demostración: `admin / Admin#2026` y `maria / Maria#2026`):

```bash
curl -s -X POST http://localhost:8000/login -H "Content-Type: application/json" \
     -d '{"usuario":"maria","password":"Maria#2026"}'
curl -s http://localhost:8000/perfil -H "Authorization: Bearer <access_token>"
```

Simular los ataques (requiere `TRUST_PROXY=true` en `.env` para poder fingir la IP de origen):

```bash
python scripts/simular_ataques.py                 # todos
python scripts/simular_ataques.py fuerza_bruta bd # solo algunos
```

Ver qué pasa por dentro:

```bash
docker compose logs security-agent | grep ALERTA
docker exec siem-kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 --topic auth.events --from-beginning
```

Consultar la auditoría (solo root de `audit-db` puede leer; el agente no):

```bash
docker exec -it siem-audit-db mysql -uroot -p bdauditoria
```
```sql
SELECT creada_en, severidad, regla, detalle, notificada FROM tbalertas ORDER BY id DESC LIMIT 20;
SELECT ocurrido_en, origen, tipo, usuario, ip FROM tbeventos ORDER BY id DESC LIMIT 20;
DELETE FROM tbeventos WHERE id = 1;   -- falla: "tbeventos es de solo insercion"
```

---

## 4. Reglas de detección

| Regla | Severidad | Se dispara cuando… | Fuente |
|---|---|---|---|
| `FUERZA_BRUTA` | Alta | Más de 5 logins fallidos desde la misma IP en 1 minuto | Auth |
| `VIAJE_IMPOSIBLE` | Alta | Un usuario entra desde dos lugares a más de 500 km que exigirían viajar a más de 900 km/h | Auth |
| `HORARIO_INUSUAL` | Media | Un `admin` inicia sesión entre las 00:00 y las 06:00 (hora local) | Auth |
| `TOKENS_INVALIDOS` | Alta | 5 peticiones con JWT inválido o ausente desde una IP en 1 minuto | Auth |
| `TOKEN_OTRA_IP` | Alta | Un JWT se usa desde una IP distinta a la que inició sesión | Auth |
| `USER_AGENT_SOSPECHOSO` | Media | El User-Agent es de una herramienta de ataque (sqlmap, hydra, nikto…) | Auth |
| `ESCALADA_PRIVILEGIOS` | Crítica | La cuenta de aplicación ejecuta `DROP`, `ALTER`, `GRANT`, `REVOKE`, `TRUNCATE`, `CREATE`… | BD |
| `EXTRACCION_MASIVA` | Alta | `SELECT` sobre una tabla sensible sin `WHERE` ni `LIMIT`, o volcado a archivo | BD |
| `CONEXION_DIRECTA` | Alta | Alguien se conecta a MySQL desde una IP que no es la de un microservicio | BD |
| `LOG_AUDITORIA_ALTERADO` | Crítica | El log de MySQL fue vaciado o desactivado | BD |

Los umbrales se cambian con variables de entorno del servicio `security-agent` en `docker-compose.yml`:
`MAX_FALLOS`, `VENTANA_FALLOS_SEG`, `VELOCIDAD_MAX_KMH`, `HORA_INUSUAL_INICIO`, `HORA_INUSUAL_FIN`,
`ZONA_HORARIA`, `ROLES_ADMIN`, `MAX_TOKENS_INVALIDOS`, `IPS_BD_PERMITIDAS`, `TABLAS_SENSIBLES`,
`APP_DB_USERS`, `ALERTA_SILENCIO_SEG` (tiempo sin repetir la misma alerta; 300 s por defecto).

Para agregar una regla: escribe un método en `security-agent/rules.py` que reciba el evento y devuelva
una lista de `Alerta`, regístralo en `MotorReglas.procesar` y añade su prueba en `tests/test_reglas.py`
(`cd security-agent && pip install pytest requests tzdata && python -m pytest -q`).

---

## 5. Estructura

```
docker-compose.yml          orquestación de los 6 contenedores
.env.example                plantilla de contraseñas y token de Telegram
mysql/init/                 crea tbusuarios y las cuentas de MySQL (mínimo privilegio)
audit-db/init/              tablas de auditoría, disparadores anti UPDATE/DELETE, cuenta solo-INSERT
auth-service/main.py        login + JWT; emite los eventos de auditoría
auth-service/audit.py       productor Kafka
db-log-shipper/shipper.py   mysql.general_log -> Kafka
security-agent/agent.py     consumidor Kafka y bucle principal
security-agent/rules.py     motor de reglas (sin E/S, con pruebas)
security-agent/notifier.py  envío a Telegram
security-agent/storage.py   escritura en audit-db
security-agent/geo.py       geolocalización de IPs
scripts/simular_ataques.py  dispara cada alerta
```

---

## 6. Limitaciones (es un proyecto de aprendizaje)

- **Extracción masiva es una heurística.** El log general de MySQL no dice cuántas filas devolvió una
  consulta, así que se detecta por la forma del `SELECT`. Un plugin de auditoría real (Percona Audit Log,
  MySQL Enterprise Audit) o `performance_schema` permitirían medir filas.
- **Kafka va sin autenticación ni cifrado.** Cualquiera dentro de la red Docker puede publicar eventos
  falsos (el simulador lo aprovecha para el escenario de las 3 AM). En producción: SASL + TLS + ACL.
- **El estado de las reglas vive en memoria** de un único agente y cada topic tiene 1 partición.
  Si el agente se reinicia, los contadores empiezan de cero (los eventos no se pierden).
- **La geolocalización usa ip-api.com** (gratis, por HTTP, uso no comercial): las IP de tus usuarios salen
  hacia un tercero. Se apaga con `GEOIP_HABILITADO=false`; la alternativa es una base local como GeoLite2.
- **"Inmutable" significa "el agente y la aplicación no pueden borrar".** El root de `audit-db` todavía
  podría hacerlo; por eso va en un servidor aparte, sin puertos y con otra contraseña.
- **`TRUST_PROXY=true` es solo para la demo.** Con él cualquiera puede fingir su IP con `X-Forwarded-For`.
- **`mysql.general_log` crece sin parar** y añade carga al motor. Para vaciarlo:
  `TRUNCATE TABLE mysql.general_log;` como root (el agente avisará con `LOG_AUDITORIA_ALTERADO`, es lo esperado).

## 7. Problemas comunes

| Síntoma | Causa probable |
|---|---|
| `tbusuarios` no existe | Los scripts de `mysql/init/` solo corren con el volumen vacío: `docker compose down -v` y vuelve a levantar. |
| Cambié una contraseña en `.env` y ya no conecta | Las cuentas se crean una sola vez; mismo remedio (`down -v`) o cámbiala también dentro de MySQL. |
| No llegan mensajes a Telegram | Revisa `docker compose logs security-agent`: 401 = token incorrecto, 400 = `chat_id` incorrecto, 403 = no le has escrito al bot. |
| `Pool overlaps with other one on this address space` | Ya usas la subred 172.28.0.0/24: cámbiala en `docker-compose.yml` (red, IPs fijas e `IPS_BD_PERMITIDAS`). |
| No salta `VIAJE_IMPOSIBLE` | Falta `TRUST_PROXY=true`, no hay salida a internet para geolocalizar, o las IP de ejemplo ya no se ubican en países distintos (cámbialas en el script). |
| `02_usuarios.sh: bad interpreter` | El archivo se guardó con saltos de línea de Windows (CRLF); guárdalo con LF. |
