#!/bin/bash
# Crea las cuentas de MySQL con el mínimo privilegio. Va en un .sh (y no en
# .sql) para tomar las contraseñas de las variables de entorno del contenedor.

mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL
-- Cuenta del microservicio de login: solo puede LEER tbusuarios.
-- Si alguien la roba, un DROP/ALTER/GRANT falla... y además queda registrado.
CREATE USER IF NOT EXISTS '${APP_DB_USER}'@'%' IDENTIFIED BY '${APP_DB_PASSWORD}';
GRANT SELECT ON bddatos.tbusuarios TO '${APP_DB_USER}'@'%';

-- Cuenta del recolector de logs: solo lee el log de auditoría del motor.
CREATE USER IF NOT EXISTS 'audit_reader'@'%' IDENTIFIED BY '${AUDIT_READER_PASSWORD}';
GRANT SELECT ON mysql.general_log TO 'audit_reader'@'%';

-- Cuenta sin privilegios para el healthcheck de Docker (solo desde el contenedor).
CREATE USER IF NOT EXISTS 'healthcheck'@'localhost';
CREATE USER IF NOT EXISTS 'healthcheck'@'127.0.0.1';
SQL
