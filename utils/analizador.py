# utils/analizador.py
import re
from collections import defaultdict
from datetime import datetime, timedelta
import random

def generar_logs_simulados(num_lineas=200):
    # Copia la función completa desde analyzer.py (sin cambios)
    logs = []
    servicios = ['sshd', 'apache2', 'nginx', 'vsftpd', 'mysql']
    ips = [f"192.168.1.{i}" for i in range(1, 20)] + [f"10.0.0.{i}" for i in range(1, 10)]
    usuarios = ['root', 'admin', 'aaron', 'user', 'test', 'guest', 'ubuntu', 'ec2-user']
    tiempo_base = datetime.now().replace(second=0, microsecond=0)
    for i in range(num_lineas):
        delta = timedelta(seconds=random.randint(1, 30))
        tiempo_actual = tiempo_base + delta * i
        timestamp = tiempo_actual.strftime("%Y-%m-%d %H:%M:%S")
        ip = random.choice(ips)
        servicio = random.choice(servicios)
        pid = random.randint(1000, 9999)
        tipo_evento = random.choices(
            ['failed', 'accepted', 'port_scan', 'normal'],
            weights=[0.3, 0.2, 0.1, 0.4]
        )[0]
        if tipo_evento == 'failed':
            usuario = random.choice(usuarios)
            mensaje = f"Failed password for {usuario} from {ip} port {random.randint(1000, 65535)}"
        elif tipo_evento == 'accepted':
            usuario = random.choice(usuarios)
            mensaje = f"Accepted password for {usuario} from {ip} port {random.randint(1000, 65535)}"
        elif tipo_evento == 'port_scan':
            puerto = random.randint(1, 1024)
            mensaje = f"Connection attempt on port {puerto} from {ip}"
        else:
            mensaje = random.choice([
                f"Session opened for user {random.choice(usuarios)} by (uid=0)",
                "Received disconnect from unknown",
                "pam_unix(sshd:session): session closed for user",
                "Server listening on 0.0.0.0 port 22."
            ])
        linea = f"{timestamp} INFO {servicio}[{pid}]: {mensaje}"
        logs.append(linea)
    return logs

def parsear_linea(linea):
    # Copia la función completa desde analyzer.py
    patron_tiempo = r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    match = re.match(patron_tiempo, linea)
    if not match:
        return None, None, None, None
    timestamp_str = match.group(1)
    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    patron_ip = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    ip_match = re.search(patron_ip, linea)
    ip = ip_match.group(1) if ip_match else None
    patron_puerto = r'port (\d+)'
    puerto_match = re.search(patron_puerto, linea)
    puerto = int(puerto_match.group(1)) if puerto_match else None
    if 'Failed password' in linea:
        evento = 'failed'
    elif 'Accepted password' in linea:
        evento = 'accepted'
    elif 'Connection attempt on port' in linea:
        evento = 'port_scan'
    else:
        evento = 'other'
    return timestamp, ip, evento, puerto

def analizar_logs(lineas, umbral_bf=5, ventana_tiempo=60, umbral_scan=5):
    stats = {
        'total_lineas': len(lineas),
        'eventos_por_ip': defaultdict(lambda: {'failed': 0, 'accepted': 0, 'port_scan': 0, 'other': 0}),
        'puertos_por_ip': defaultdict(set),
        'timestamps_por_ip': defaultdict(list),
        'ips_sospechosas_bf': set(),
        'ips_sospechosas_scan': set(),
    }
    for linea in lineas:
        timestamp, ip, evento, puerto = parsear_linea(linea)
        if not ip:
            continue
        stats['eventos_por_ip'][ip][evento] += 1
        if puerto:
            stats['puertos_por_ip'][ip].add(puerto)
        if evento == 'failed':
            stats['timestamps_por_ip'][ip].append(timestamp)
    # Detectar fuerza bruta
    for ip, timestamps in stats['timestamps_por_ip'].items():
        timestamps.sort()
        for i in range(len(timestamps)):
            count = 1
            for j in range(i+1, len(timestamps)):
                if (timestamps[j] - timestamps[i]).total_seconds() <= ventana_tiempo:
                    count += 1
                else:
                    break
            if count >= umbral_bf:
                stats['ips_sospechosas_bf'].add(ip)
                break
    # Detectar escaneo
    for ip, puertos in stats['puertos_por_ip'].items():
        if len(puertos) >= umbral_scan:
            stats['ips_sospechosas_scan'].add(ip)
    return stats