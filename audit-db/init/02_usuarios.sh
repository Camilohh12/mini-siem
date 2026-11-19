#!/bin/bash
# Cuenta del agente de seguridad: solo INSERT. No puede leer, modificar ni borrar.

mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL
CREATE USER IF NOT EXISTS 'audit_writer'@'%' IDENTIFIED BY '${AUDIT_WRITER_PASSWORD}';
GRANT INSERT ON bdauditoria.tbeventos TO 'audit_writer'@'%';
GRANT INSERT ON bdauditoria.tbalertas TO 'audit_writer'@'%';

CREATE USER IF NOT EXISTS 'healthcheck'@'localhost';
CREATE USER IF NOT EXISTS 'healthcheck'@'127.0.0.1';
SQL
