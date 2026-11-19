-- Se ejecuta una sola vez, la primera vez que arranca el contenedor
-- (cuando el volumen de datos está vacío). La base bddatos ya existe porque
-- docker-compose define MYSQL_DATABASE=bddatos.

USE bddatos;

CREATE TABLE IF NOT EXISTS tbusuarios (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  usuario       VARCHAR(50)  NOT NULL UNIQUE,
  email         VARCHAR(120) NOT NULL UNIQUE,
  password_hash VARCHAR(100) NOT NULL,              -- bcrypt, nunca texto plano
  rol           ENUM('admin', 'usuario') NOT NULL DEFAULT 'usuario',
  activo        TINYINT(1)   NOT NULL DEFAULT 1,
  creado_en     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Usuarios de DEMOSTRACIÓN. Cámbialos o bórralos fuera de un entorno de prueba.
--   admin / Admin#2026      maria / Maria#2026
INSERT INTO tbusuarios (usuario, email, password_hash, rol) VALUES
  ('admin', 'admin@ejemplo.com', '$2b$12$PbkOfp/QrVaSjAandlW5fu8WqQDM87ewuCsRlBvPaThHI08dHHc/6', 'admin'),
  ('maria', 'maria@ejemplo.com', '$2b$12$WZrErdNGoeKhj7W0PU6pDezKowyh6jTylddyGxuVk.FM7sLXm3tIG', 'usuario');
