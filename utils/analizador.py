# utils/analizador.py
import re
from collections import defaultdict
# utils/analizador.py
import gzip
import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_IP_CANDIDATE = re.compile(r"(?<![\w:.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,39})(?![\w:.])")
_SYSLOG_TIME = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
_ISO_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)")
_APACHE_TIME = re.compile(r"\[([^]]+)\]")
_HTTP_STATUS = re.compile(r'"[^"\r\n]*"\s+(\d{3})(?:\s|$)')
_HTTP_PATH = re.compile(r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^ ?"]+)', re.IGNORECASE)
_TARGET_PORT = re.compile(r"(?:\bDPT|dstport|destination_port|to port)\s*[=: ]\s*(\d{1,5})", re.IGNORECASE)


def _parsear_fecha(linea):
    match = _ISO_TIME.match(linea)
    if match:
        valor = match.group(1).replace("Z", "+00:00")
        try:
            fecha = datetime.fromisoformat(valor)
            return fecha.astimezone(timezone.utc).replace(tzinfo=None) if fecha.tzinfo else fecha
        except ValueError:
            return None

    match = _APACHE_TIME.search(linea)
    if match:
        try:
            fecha = datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S %z")
            return fecha.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            pass

    match = _SYSLOG_TIME.match(linea)
    if match:
        try:
            return datetime.strptime(f"{datetime.now().year} {match.group(1)}", "%Y %b %d %H:%M:%S")
        except ValueError:
            pass
    return None


def _extraer_ip(linea):
    campos = linea.split()
    if len(campos) >= 8 and campos[2].upper() in {"ALLOW", "DROP", "DENY", "REJECT"} and campos[3].upper() in {"TCP", "UDP", "ICMP", "ICMPV6"}:
        try:
            return str(ipaddress.ip_address(campos[4]))
        except ValueError:
            pass
    apache_ip = re.match(r"^\s*(\S+)", linea)
    ssh_ip = re.search(r"\bfrom\s+([0-9a-fA-F:.]+)", linea, re.IGNORECASE)
    candidatos = []
    if apache_ip:
        candidatos.append(apache_ip.group(1))
    if ssh_ip:
        candidatos.append(ssh_ip.group(1))
    candidatos.extend(match.group(0) for match in _IP_CANDIDATE.finditer(linea))
    for candidato in candidatos:
        try:
            return str(ipaddress.ip_address(candidato.strip("[]")))
        except ValueError:
            continue
    return None


def _extraer_puerto_objetivo(linea):
    campos = linea.split()
    if len(campos) >= 8 and campos[2].upper() in {"ALLOW", "DROP", "DENY", "REJECT"} and campos[3].upper() in {"TCP", "UDP"}:
        if campos[7].isdigit() and 1 <= int(campos[7]) <= 65535:
            return int(campos[7])
    match = _TARGET_PORT.search(linea)
    if not match and re.search(r"connection attempt on port", linea, re.IGNORECASE):
        match = re.search(r"\bport\s+(\d{1,5})", linea, re.IGNORECASE)
    if not match:
        return None
    puerto = int(match.group(1))
    return puerto if 1 <= puerto <= 65535 else None


def parsear_linea(linea):
    """Extrae fecha, IP de origen, categoría y puerto de destino de syslog/web/firewall."""
    timestamp = _parsear_fecha(linea)
    ip = _extraer_ip(linea)
    puerto = _extraer_puerto_objetivo(linea)
    status_match = _HTTP_STATUS.search(linea)
    status = int(status_match.group(1)) if status_match else None

    if puerto is not None:
        evento = "port_scan"
    elif re.search(r"failed password|authentication failure|failed login|invalid user", linea, re.IGNORECASE):
        evento = "failed"
    elif re.search(r"accepted (?:password|publickey)|login successful", linea, re.IGNORECASE):
        evento = "accepted"
    elif status == 401:
        evento = "failed"
    elif status is not None and status >= 400:
        evento = "web_error"
    else:
        evento = "other"
    return timestamp, ip, evento, puerto


def _umbral_en_ventana(timestamps, umbral, ventana_tiempo):
    timestamps.sort()
    inicio = 0
    for fin, timestamp in enumerate(timestamps):
        while (timestamp - timestamps[inicio]).total_seconds() > ventana_tiempo:
            inicio += 1
        if fin - inicio + 1 >= umbral:
            return True
    return False


def analizar_logs(lineas, umbral_bf=5, ventana_tiempo=60, umbral_scan=5, umbral_web=10):
    """Analiza líneas de auth/syslog, Apache/Nginx y firewall sin modificar la entrada."""
    eventos = lambda: {"failed": 0, "accepted": 0, "port_scan": 0, "web_error": 0, "other": 0}
    stats = {
        "total_lineas": len(lineas),
        "lineas_reconocidas": 0,
        "eventos_por_ip": defaultdict(eventos),
        "puertos_por_ip": defaultdict(set),
        "timestamps_por_ip": defaultdict(list),
        "errores_web_por_ip": defaultdict(int),
        "rutas_404_por_ip": defaultdict(set),
        "ips_sospechosas_bf": set(),
        "ips_sospechosas_scan": set(),
        "ips_sospechosas_web": set(),
    }

    for linea in lineas:
        timestamp, ip, evento, puerto = parsear_linea(linea)
        if not ip:
            continue
        stats["lineas_reconocidas"] += 1
        stats["eventos_por_ip"][ip][evento] += 1
        if puerto is not None:
            stats["puertos_por_ip"][ip].add(puerto)
        if evento == "failed" and timestamp is not None:
            stats["timestamps_por_ip"][ip].append(timestamp)
        status_match = _HTTP_STATUS.search(linea)
        if status_match and int(status_match.group(1)) >= 400:
            stats["errores_web_por_ip"][ip] += 1
            path_match = _HTTP_PATH.search(linea)
            if status_match.group(1) == "404" and path_match:
                stats["rutas_404_por_ip"][ip].add(path_match.group(1))

    for ip, timestamps in stats["timestamps_por_ip"].items():
        if _umbral_en_ventana(timestamps, umbral_bf, ventana_tiempo):
            stats["ips_sospechosas_bf"].add(ip)
    for ip, puertos in stats["puertos_por_ip"].items():
        if len(puertos) >= umbral_scan:
            stats["ips_sospechosas_scan"].add(ip)
    for ip, rutas in stats["rutas_404_por_ip"].items():
        if len(rutas) >= umbral_web:
            stats["ips_sospechosas_web"].add(ip)
    return stats


def leer_archivo_logs(ruta):
    """Lee logs de texto y rotaciones gzip con decodificación tolerante."""
    ruta = Path(ruta)
    abrir = gzip.open if ruta.suffix.lower() == ".gz" else open
    with abrir(ruta, "rt", encoding="utf-8-sig", errors="replace") as archivo:
        return archivo.read().splitlines()


def leer_logs_subidos(contenido, nombre_archivo):
    """Decodifica la carga de Streamlit, incluidos archivos .gz."""
    if nombre_archivo.lower().endswith(".gz"):
        contenido = gzip.decompress(contenido)
    return contenido.decode("utf-8-sig", errors="replace").splitlines()