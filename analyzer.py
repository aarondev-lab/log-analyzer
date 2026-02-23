#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Analizador de logs de seguridad.
Este es un script de python donde busco detectar fuerza bruta y escaneos de puertos, 
ya sea con logs de verdad o generando unos falsos para probar.
"""
import argparse
import random
import re
import sys
import time
import os
import webbrowser  # Este lo he añadido para que me abra el informe automáticamente, que es más cómodo
from collections import defaultdict
from datetime import datetime, timedelta

# Para el informe en HTML uso Jinja2, que me permite separar el diseño del código
from jinja2 import Environment, FileSystemLoader

# Intento importar tqdm para la barra de progreso, si no está, aviso pero el script sigue funcionando
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    print("[!] Si quieres una barra de progreso más chula, instala tqdm: pip install tqdm", file=sys.stderr)

# ===================== CONFIGURACIÓN =====================
# Estos valores los puedo ajustar según lo que considere un ataque
UMBRAL_FUERZA_BRUTA = 5      # Si desde una IP hay más de 5 intentos fallidos en poco tiempo, lo marco
VENTANA_TIEMPO = 60           # La ventana de tiempo para contar esos intentos (en segundos)
PUERTOS_ESCANEO = 5           # Si una IP toca más de 5 puertos distintos, lo considero escaneo

# ===================== GENERADOR DE LOGS SIMULADOS =====================
def generar_logs_simulados(num_lineas=200):
    """
    Aquí genero logs falsos para probar el programa, con formato de fecha y mensajes típicos.
    Así no necesito tener un archivo de log real para hacer pruebas.
    """
    logs = []
    servicios = ['sshd', 'apache2', 'nginx', 'vsftpd', 'mysql']
    # Me invento un montón de IPs de redes privadas para que parezca real
    ips = [f"192.168.1.{i}" for i in range(1, 20)] + [f"10.0.0.{i}" for i in range(1, 10)]
    usuarios = ['root', 'admin', 'aaron', 'user', 'test', 'guest', 'ubuntu', 'ec2-user']

    # Para que los tiempos tengan sentido, los genero dentro de la última hora
    tiempo_base = datetime.now().replace(second=0, microsecond=0)

    for i in range(num_lineas):
        # Cada línea va con un pequeño desfase de tiempo para que no sean todas iguales
        delta = timedelta(seconds=random.randint(1, 30))
        tiempo_actual = tiempo_base + delta * i
        timestamp = tiempo_actual.strftime("%Y-%m-%d %H:%M:%S")

        ip = random.choice(ips)
        servicio = random.choice(servicios)
        pid = random.randint(1000, 9999)

        # Aquí decido aleatoriamente qué tipo de evento va a ser, con más probabilidad de cosas normales
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
            # Para simular un escaneo, hago que se conecte a un puerto aleatorio (normalmente bajos)
            puerto = random.randint(1, 1024)
            mensaje = f"Connection attempt on port {puerto} from {ip}"
        else:
            # Eventos normales, típicos de logs de sistemas
            mensaje = random.choice([
                f"Session opened for user {random.choice(usuarios)} by (uid=0)",
                "Received disconnect from unknown",
                "pam_unix(sshd:session): session closed for user",
                "Server listening on 0.0.0.0 port 22."
            ])

        linea = f"{timestamp} INFO {servicio}[{pid}]: {mensaje}"
        logs.append(linea)

    return logs

# = ANÁLISIS DE LOGS =
def parsear_linea(linea):
    """
    Esta función es la que se encarga de sacar la información útil de cada línea:
    timestamp, IP, tipo de evento y puerto (si lo hay).
    Si no encuentra algo, devuelve None.
    """
    # Primero busco la fecha al principio de la línea
    patron_tiempo = r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    match = re.match(patron_tiempo, linea)
    if not match:
        return None, None, None, None
    timestamp_str = match.group(1)
    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

    # Luego intento encontrar una IP
    patron_ip = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    ip_match = re.search(patron_ip, linea)
    ip = ip_match.group(1) if ip_match else None

    # Y también un puerto, si aparece
    patron_puerto = r'port (\d+)'
    puerto_match = re.search(patron_puerto, linea)
    puerto = int(puerto_match.group(1)) if puerto_match else None

    # Clasifico el evento según el contenido del mensaje
    if 'Failed password' in linea:
        evento = 'failed'
    elif 'Accepted password' in linea:
        evento = 'accepted'
    elif 'Connection attempt on port' in linea:
        evento = 'port_scan'
    else:
        evento = 'other'

    return timestamp, ip, evento, puerto

def analizar_logs(lineas):
    """
    Aquí es donde hago el análisis gordo. Proceso línea por línea, voy acumulando estadísticas
    y al final detecto IPs sospechosas.
    """
    stats = {
        'total_lineas': len(lineas),
        'eventos_por_ip': defaultdict(lambda: {'failed': 0, 'accepted': 0, 'port_scan': 0, 'other': 0}),
        'puertos_por_ip': defaultdict(set),
        'timestamps_por_ip': defaultdict(list),  # Esto es para luego calcular la fuerza bruta por tiempo
        'ips_sospechosas_bf': set(),
        'ips_sospechosas_scan': set(),
    }

    # Si tengo tqdm (librería para generar barra de progreso), genera la barra que se ve má realista.
    iterador = tqdm(lineas, desc="Analizando logs", unit=" líneas") if HAS_TQDM else lineas

    for linea in iterador:
        time.sleep(0.75)  # Este sleep sirve para no generar saturación en el proceso (importante por si tiramos un nmap)
        timestamp, ip, evento, puerto = parsear_linea(linea)
        if not ip:
            continue  # Si no hay IP, me salto la línea, no me sirve

        # Voy llenando las estadísticas
        stats['eventos_por_ip'][ip][evento] += 1
        if puerto:
            stats['puertos_por_ip'][ip].add(puerto)
        if evento == 'failed':
            stats['timestamps_por_ip'][ip].append(timestamp)

    # Detectar fuerza bruta: miro si hay muchos fallos en poco tiempo desde la misma IP
    for ip, timestamps in stats['timestamps_por_ip'].items():
        timestamps.sort()
        for i in range(len(timestamps)):
            count = 1
            for j in range(i+1, len(timestamps)):
                if (timestamps[j] - timestamps[i]).total_seconds() <= VENTANA_TIEMPO:
                    count += 1
                else:
                    break
            if count >= UMBRAL_FUERZA_BRUTA:
                stats['ips_sospechosas_bf'].add(ip)
                break  # Una vez que sé que es sospechosa, no necesito seguir mirando

    # Detectar escaneo: si una IP ha tocado muchos puertos distintos
    for ip, puertos in stats['puertos_por_ip'].items():
        if len(puertos) >= PUERTOS_ESCANEO:
            stats['ips_sospechosas_scan'].add(ip)

    return stats

def generar_reporte_consola(stats):
    """
    Saco un informe por consola con los resultados más importantes.
    Es como un resumen rápido para verlo sin abrir el HTML.
    """
    print("\n" + "="*60)
    print(" INFORME DE ANÁLISIS DE LOGS".center(60))
    print("="*60)

    print(f"\n Líneas procesadas: {stats['total_lineas']}")
    print(f" IPs únicas detectadas: {len(stats['eventos_por_ip'])}")

    print("\n IPs sospechosas de FUERZA BRUTA:")
    if stats['ips_sospechosas_bf']:
        for ip in sorted(stats['ips_sospechosas_bf']):
            fallos = stats['eventos_por_ip'][ip]['failed']
            print(f"   - {ip} ({fallos} intentos fallidos)")
    else:
        print("   No se detectaron ataques de fuerza bruta.")

    print("\n IPs sospechosas de ESCANEO DE PUERTOS:")
    if stats['ips_sospechosas_scan']:
        for ip in sorted(stats['ips_sospechosas_scan']):
            puertos = sorted(stats['puertos_por_ip'][ip])
            print(f"   - {ip} (puertos: {', '.join(map(str, puertos[:5]))}{'...' if len(puertos)>5 else ''})")
    else:
        print("   No se detectaron escaneos de puertos.")

    print("\n Resumen de eventos por IP (top 5):")
    top_ips = sorted(stats['eventos_por_ip'].items(), key=lambda x: sum(x[1].values()), reverse=True)[:5]
    for ip, eventos in top_ips:
        total = sum(eventos.values())
        print(f"   {ip}: {total} eventos (failed: {eventos['failed']}, accepted: {eventos['accepted']}, scan: {eventos['port_scan']})")

    print("\n" + "="*60)

def generar_reporte_html(stats, archivo_salida="logs_report.html"):
    """
    Esta es la función que me genera el informe en HTML con un diseño más profesional.
    Uso Jinja2 para rellenar la plantilla que tengo en la carpeta templates.
    Además, al final lo abro automáticamente en el navegador para no tener que buscarlo.
    """
    # Preparo el entorno de Jinja2 apuntando a la carpeta templates
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template('reporte.html')

    # Calculo el top 5 de IPs por actividad para mostrarlo en el informe
    top_ips = sorted(stats['eventos_por_ip'].items(), key=lambda x: sum(x[1].values()), reverse=True)[:5]

    # Fecha de generación con formato legible
    fecha_generacion = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # Relleno la plantilla con los datos
    html_content = template.render(
        stats=stats,
        top_ips=top_ips,
        total_lineas=stats['total_lineas'],
        fecha_generacion=fecha_generacion
    )

    # Guardo el archivo HTML en el directorio actual
    with open(archivo_salida, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f" Informe HTML generado: {archivo_salida}")

    # Intento abrirlo en el navegador por defecto
    try:
        webbrowser.open(archivo_salida)
        print(" Abriendo informe en el navegador...")
    except Exception as e:
        print(f"[!] No se pudo abrir el navegador automáticamente: {e}")

# = MAIN CODE =
def main():
    """
    Aquí es donde empieza todo. Recojo los argumentos de la terminal,
    decido si uso un archivo real o genero logs falsos, y lanzo el análisis.
    """
    parser = argparse.ArgumentParser(description="Mi analizador de logs de seguridad")
    parser.add_argument('archivo', nargs='?', help="Archivo de log a analizar (si no se especifica, se generan logs simulados)")
    parser.add_argument('-n', '--num-lineas', type=int, default=200, help="Número de líneas a generar si no hay archivo (default: 200)")
    parser.add_argument('--no-html', action='store_true', help="Si no quiero que genere el HTML, solo consola")
    args = parser.parse_args()

    if args.archivo:
        # Si me pasaron un archivo, intento leerlo
        try:
            with open(args.archivo, 'r', encoding='utf-8') as f:
                lineas = f.readlines()
            print(f"[+] Leyendo {len(lineas)} líneas de {args.archivo}")
        except FileNotFoundError:
            print(f"[!] Archivo no encontrado: {args.archivo}")
            sys.exit(1)
    else:
        # Si no, genero logs simulados con el número de líneas indicado
        print(f"[+] Generando {args.num_lineas} líneas de log simuladas...")
        lineas = generar_logs_simulados(args.num_lineas)

    # Proceso las líneas y obtengo las estadísticas
    stats = analizar_logs(lineas)

    # Muestro el informe en consola (siempre lo hago)
    generar_reporte_consola(stats)

    # Si no me pidieron lo contrario, genero también el informe HTML
    if not args.no_html:
        generar_reporte_html(stats)

if __name__ == "__main__":
    main()