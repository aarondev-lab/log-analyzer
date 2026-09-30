"""Consultas opcionales de reputación de IP mediante AbuseIPDB."""
import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

_API_URL = "https://api.abuseipdb.com/api/v2/check"


def _ip_publica(valor):
    try:
        direccion = ipaddress.ip_address(valor)
    except ValueError:
        return None
    return str(direccion) if direccion.is_global else None


def _consultar_ip(ip, api_key, max_age_days):
    query = urlencode({"ipAddress": ip, "maxAgeInDays": max_age_days})
    request = Request(
        f"{_API_URL}?{query}",
        headers={"Key": api_key, "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        try:
            payload = json.loads(error.read().decode("utf-8"))
            detalle = payload.get("errors", [{}])[0].get("detail", "Error de la API")
        except (ValueError, IndexError, AttributeError):
            detalle = f"La API respondió con HTTP {error.code}"
        raise RuntimeError(detalle) from None
    except URLError as error:
        raise RuntimeError(f"No se pudo conectar con AbuseIPDB: {error.reason}") from None
    except TimeoutError:
        raise RuntimeError("La consulta a AbuseIPDB agotó el tiempo de espera") from None

    datos = payload["data"]
    return {
        "ip": ip,
        "score": int(datos.get("abuseConfidenceScore", 0)),
        "reportes": int(datos.get("totalReports", 0)),
        "ultimo_reporte": datos.get("lastReportedAt") or "Sin reportes recientes",
        "pais": datos.get("countryCode") or "-",
        "isp": datos.get("isp") or "-",
    }


def consultar_ips_publicas(ips, api_key, max_ips=20, max_age_days=90):
    """Consulta hasta max_ips direcciones globales y devuelve metadatos agregados."""
    if not api_key or not api_key.strip():
        raise ValueError("Configura ABUSEIPDB_API_KEY para consultar reputación.")
    if not 1 <= max_age_days <= 365:
        raise ValueError("max_age_days debe estar entre 1 y 365.")
    if not 1 <= max_ips <= 50:
        raise ValueError("max_ips debe estar entre 1 y 50.")

    direcciones = []
    vistas = set()
    for valor in ips:
        direccion = _ip_publica(valor)
        if direccion and direccion not in vistas:
            direcciones.append(direccion)
            vistas.add(direccion)
    seleccionadas = direcciones[:max_ips]
    resultados = []
    if seleccionadas:
        with ThreadPoolExecutor(max_workers=min(5, len(seleccionadas))) as executor:
            trabajos = {
                executor.submit(_consultar_ip, direccion, api_key.strip(), max_age_days): direccion
                for direccion in seleccionadas
            }
            for trabajo in as_completed(trabajos):
                direccion = trabajos[trabajo]
                try:
                    resultados.append(trabajo.result())
                except (RuntimeError, KeyError, ValueError) as error:
                    resultados.append({"ip": direccion, "error": str(error)})

    resultados.sort(key=lambda item: ("error" in item, -item.get("score", 0), item["ip"]))
    return {
        "resultados": resultados,
        "ips_publicas": len(direcciones),
        "omitidas_no_publicas": len(set(ips)) - len(direcciones),
        "omitidas_por_limite": max(0, len(direcciones) - len(seleccionadas)),
    }


def generar_reglas_bloqueo(ips, plataforma):
    """Genera reglas revisables; nunca ejecuta cambios en el firewall."""
    direcciones = sorted({direccion for valor in ips if (direccion := _ip_publica(valor))})
    if plataforma == "Windows Defender Firewall (PowerShell)":
        lineas = ["# Revisa cada regla antes de ejecutarla en PowerShell como administrador."]
        lineas.extend(
            f"New-NetFirewallRule -DisplayName 'Logwatch block {direccion}' -Direction Inbound -Action Block -RemoteAddress '{direccion}' -Profile Any"
            for direccion in direcciones
        )
        return "\n".join(lineas) + "\n", "block_ips.ps1"
    if plataforma == "Linux UFW":
        lineas = ["#!/usr/bin/env bash", "# Revisa las IP antes de ejecutar con sudo."]
        lineas.extend(
            f"sudo ufw insert 1 deny from {direccion} to any comment 'Logwatch reputation block'"
            for direccion in direcciones
        )
        return "\n".join(lineas) + "\n", "block_ips.sh"
    raise ValueError("Plataforma de firewall no admitida.")
