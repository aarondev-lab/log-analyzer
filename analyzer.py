#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Analizador local de logs de autenticación, web y firewall."""
import argparse
import shutil
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from utils.analizador import analizar_logs, leer_archivo_logs

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    HAS_RICH = True
except ImportError:
    HAS_RICH = False


def _positivo(valor):
    numero = int(valor)
    if numero < 1:
        raise argparse.ArgumentTypeError("el valor debe ser mayor que cero")
    return numero


def generar_reporte_consola(stats, fuente):
    total_alertas = len(stats["ips_sospechosas_bf"] | stats["ips_sospechosas_scan"] | stats["ips_sospechosas_web"])
    if not HAS_RICH:
        print("\nLOGWATCH | INFORME DE ANÁLISIS")
        print("=" * 72)
        print(f"Fuente: {fuente}")
        print(f"Líneas leídas: {stats['total_lineas']:,} | IPs: {len(stats['eventos_por_ip']):,} | Alertas: {total_alertas:,}")
        secciones = (
            ("FUERZA BRUTA", stats["ips_sospechosas_bf"]),
            ("ESCANEO DE PUERTOS", stats["ips_sospechosas_scan"]),
            ("SONDEO WEB", stats["ips_sospechosas_web"]),
        )
        for titulo, ips in secciones:
            print(f"\n{titulo}")
            if ips:
                for ip in sorted(ips):
                    print(f"  {ip}")
            else:
                print("  Sin alertas")
        print("=" * 72)
        return

    consola = Console()
    resumen = Table.grid(padding=(0, 2))
    resumen.add_column(style="dim")
    resumen.add_column(style="bold")
    resumen.add_row("Fuente", fuente)
    resumen.add_row("Líneas", f"{stats['total_lineas']:,}")
    resumen.add_row("Líneas con IP", f"{stats['lineas_reconocidas']:,}")
    resumen.add_row("IPs únicas", f"{len(stats['eventos_por_ip']):,}")
    resumen.add_row("IPs con alertas", f"{total_alertas:,}")
    consola.print(Panel(resumen, title="LOGWATCH  /  INFORME DE ANÁLISIS", border_style="bright_green"))

    alertas = Table(box=None, expand=True)
    alertas.add_column("CLASIFICACIÓN", style="bold")
    alertas.add_column("IP DE ORIGEN", style="cyan")
    alertas.add_column("EVIDENCIA", overflow="fold")
    filas = 0
    for ip in sorted(stats["ips_sospechosas_bf"]):
        alertas.add_row("Fuerza bruta", ip, f"{stats['eventos_por_ip'][ip]['failed']} fallos de autenticación")
        filas += 1
    for ip in sorted(stats["ips_sospechosas_scan"]):
        puertos = ", ".join(map(str, sorted(stats["puertos_por_ip"][ip])))
        alertas.add_row("Escaneo de puertos", ip, f"{len(stats['puertos_por_ip'][ip])} puertos destino: {puertos}")
        filas += 1
    for ip in sorted(stats["ips_sospechosas_web"]):
        alertas.add_row("Sondeo web", ip, f"{len(stats['rutas_404_por_ip'][ip])} rutas 404 distintas")
        filas += 1
    if not filas:
        alertas.add_row("Sin alertas", "-", "Ningún umbral de detección fue superado")
    consola.print(alertas)

    actividad = Table(title="IPs con mayor actividad", header_style="bold bright_green", expand=True)
    actividad.add_column("IP", style="cyan")
    actividad.add_column("Eventos", justify="right")
    actividad.add_column("Fallos", justify="right")
    actividad.add_column("Accesos", justify="right")
    actividad.add_column("Errores web", justify="right")
    for ip, eventos in sorted(stats["eventos_por_ip"].items(), key=lambda item: sum(item[1].values()), reverse=True)[:8]:
        actividad.add_row(ip, str(sum(eventos.values())), str(eventos["failed"]), str(eventos["accepted"]), str(eventos["web_error"]))
    consola.print(actividad)


def generar_reporte_html(stats, archivo_salida):
    template_dir = Path(__file__).parent / "templates"
    entorno = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
    plantilla = entorno.get_template("reporte.html")
    top_ips = sorted(stats["eventos_por_ip"].items(), key=lambda item: sum(item[1].values()), reverse=True)[:8]
    destino = Path(archivo_salida).resolve()
    destino.parent.mkdir(parents=True, exist_ok=True)
    css_origen = Path(__file__).parent / "assets" / "reporte.css"
    css_destino = destino.parent / "assets" / "reporte.css"
    if css_origen.resolve() != css_destino.resolve():
        css_destino.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(css_origen, css_destino)
    destino.write_text(
        plantilla.render(
            stats=stats,
            top_ips=top_ips,
            total_lineas=stats["total_lineas"],
            fecha_generacion=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        ),
        encoding="utf-8",
    )
    return destino


def main():
    parser = argparse.ArgumentParser(
        description="Analiza logs reales de autenticación, servidores web y firewall.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("archivo", help="Ruta a un log de texto o una rotación .gz")
    parser.add_argument("--umbral-bf", type=_positivo, default=5, help="Fallos de autenticación dentro de la ventana")
    parser.add_argument("--ventana", type=_positivo, default=60, help="Ventana de fuerza bruta, en segundos")
    parser.add_argument("--umbral-scan", type=_positivo, default=5, help="Puertos de destino distintos para alertar")
    parser.add_argument("--umbral-web", type=_positivo, default=10, help="Rutas 404 distintas para alertar")
    parser.add_argument("--html", nargs="?", const="logs_report.html", metavar="RUTA", help="Genera un informe HTML (ruta opcional)")
    parser.add_argument("--abrir-html", action="store_true", help="Abre el informe HTML al terminar")
    args = parser.parse_args()
    if args.abrir_html and not args.html:
        parser.error("--abrir-html requiere --html")

    try:
        lineas = leer_archivo_logs(args.archivo)
    except (OSError, EOFError) as error:
        parser.error(f"no se pudo leer '{args.archivo}': {error}")

    stats = analizar_logs(lineas, args.umbral_bf, args.ventana, args.umbral_scan, args.umbral_web)
    generar_reporte_consola(stats, args.archivo)
    if args.html:
        destino = generar_reporte_html(stats, args.html)
        print(f"\nInforme HTML: {destino}")
        if args.abrir_html:
            webbrowser.open(destino.as_uri())
    if not stats["lineas_reconocidas"]:
        print("\nAviso: no se encontraron direcciones IP reconocibles en el archivo.", file=sys.stderr)


if __name__ == "__main__":
    main()