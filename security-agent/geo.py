"""Geolocalización de direcciones IP (para la regla de "viaje imposible").

Usa el servicio gratuito ip-api.com (sin clave, ~45 consultas/min, solo HTTP
y solo para uso no comercial). Las IP privadas no se consultan. Los
resultados se guardan en memoria para no repetir consultas.

Para producción conviene una base local (p. ej. MaxMind GeoLite2) y así no
enviar las IP de tus usuarios a un tercero.
"""

import ipaddress
import logging

import requests

log = logging.getLogger("geo")


class Geolocalizador:
    def __init__(self, url: str = "http://ip-api.com/json/{ip}", max_cache: int = 5000):
        self._url = url
        self._cache: dict[str, dict | None] = {}
        self._max_cache = max_cache

    def localizar(self, ip: str) -> dict | None:
        """Devuelve {"lat", "lon", "pais", "ciudad"} o None si no se pudo ubicar."""
        try:
            if not ipaddress.ip_address(ip).is_global:
                return None  # IP privada, loopback, reservada...
        except ValueError:
            return None
        if ip in self._cache:
            return self._cache[ip]

        ubicacion = None
        try:
            r = requests.get(
                self._url.format(ip=ip),
                params={"fields": "status,country,city,lat,lon"},
                timeout=3,
            )
            datos = r.json()
            if r.status_code == 200 and datos.get("status") == "success":
                ubicacion = {
                    "lat": float(datos["lat"]),
                    "lon": float(datos["lon"]),
                    "pais": datos.get("country", ""),
                    "ciudad": datos.get("city", ""),
                }
        except (requests.RequestException, ValueError, KeyError) as error:
            log.warning("No se pudo geolocalizar %s: %s", ip, type(error).__name__)
            return None  # fallo temporal: no se guarda en caché

        if len(self._cache) >= self._max_cache:
            self._cache.clear()
        self._cache[ip] = ubicacion
        return ubicacion
