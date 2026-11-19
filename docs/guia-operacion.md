# Guía de operación

Comandos del día a día, configuración de Telegram, consultas a la auditoría y solución de problemas. Para la visión general del proyecto, ver el [README](../README.md).

## 1. MySQL con Docker

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

**En este proyecto** MySQL se lanza con Compose (sección 2 de esta guía). Comandos del día a día:

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

## 4. Problemas comunes

| Síntoma | Causa probable |
|---|---|
| `tbusuarios` no existe | Los scripts de `mysql/init/` solo corren con el volumen vacío: `docker compose down -v` y vuelve a levantar. |
| Cambié una contraseña en `.env` y ya no conecta | Las cuentas se crean una sola vez; mismo remedio (`down -v`) o cámbiala también dentro de MySQL. |
| No llegan mensajes a Telegram | Revisa `docker compose logs security-agent`: 401 = token incorrecto, 400 = `chat_id` incorrecto, 403 = no le has escrito al bot. |
| `Pool overlaps with other one on this address space` | Ya usas la subred 172.28.0.0/24: cámbiala en `docker-compose.yml` (red, IPs fijas e `IPS_BD_PERMITIDAS`). |
| No salta `VIAJE_IMPOSIBLE` | Falta `TRUST_PROXY=true`, no hay salida a internet para geolocalizar, o las IP de ejemplo ya no se ubican en países distintos (cámbialas en el script). |
| `02_usuarios.sh: bad interpreter` | El archivo se guardó con saltos de línea de Windows (CRLF); guárdalo con LF. |
