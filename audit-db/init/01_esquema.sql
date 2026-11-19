-- Almacenamiento de auditoría "append-only": se puede insertar, pero no
-- modificar ni borrar. Dos barreras:
--   1) la cuenta del agente (audit_writer) solo tiene privilegio INSERT;
--   2) disparadores que rechazan UPDATE y DELETE aunque la cuenta tuviera permiso.

USE bdauditoria;

-- Todos los eventos recibidos, tal cual llegaron.
CREATE TABLE IF NOT EXISTS tbeventos (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  event_id    CHAR(36)     NOT NULL UNIQUE,          -- evita duplicados si Kafka reentrega
  recibido_en TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  ocurrido_en DATETIME(6)  NOT NULL,                 -- hora del evento en UTC
  origen      VARCHAR(40)  NOT NULL,                 -- auth-service | mysql
  tipo        VARCHAR(40)  NOT NULL,                 -- login_failed, db_query, ...
  usuario     VARCHAR(100) NULL,
  ip          VARCHAR(45)  NULL,
  payload     JSON         NOT NULL,
  INDEX idx_ocurrido (ocurrido_en),
  INDEX idx_tipo (tipo),
  INDEX idx_ip (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Alertas generadas por el agente.
CREATE TABLE IF NOT EXISTS tbalertas (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  alerta_id   CHAR(36)     NOT NULL UNIQUE,
  creada_en   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  regla       VARCHAR(40)  NOT NULL,
  severidad   VARCHAR(10)  NOT NULL,
  titulo      VARCHAR(200) NOT NULL,
  detalle     TEXT         NOT NULL,
  clave       VARCHAR(200) NOT NULL,                 -- a quién/qué se refiere
  event_id    CHAR(36)     NULL,                     -- evento que la disparó
  notificada  TINYINT(1)   NOT NULL,                 -- 1 = llegó a Telegram
  INDEX idx_regla (regla),
  INDEX idx_creada (creada_en)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TRIGGER tbeventos_sin_update BEFORE UPDATE ON tbeventos FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'tbeventos es de solo insercion';
CREATE TRIGGER tbeventos_sin_delete BEFORE DELETE ON tbeventos FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'tbeventos es de solo insercion';
CREATE TRIGGER tbalertas_sin_update BEFORE UPDATE ON tbalertas FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'tbalertas es de solo insercion';
CREATE TRIGGER tbalertas_sin_delete BEFORE DELETE ON tbalertas FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'tbalertas es de solo insercion';
