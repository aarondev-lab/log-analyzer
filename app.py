# app.py
import os

import pandas as pd
import streamlit as st

from utils.analizador import analizar_logs, leer_logs_subidos
from utils.reputacion import consultar_ips_publicas, generar_reglas_bloqueo

st.set_page_config(page_title="Logwatch | Security Analysis", page_icon="◉", layout="wide")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700&display=swap');
:root { color-scheme: dark; }
.stApp { background: #101614; color: #e7eeea; font-family: 'DM Sans', sans-serif; }
[data-testid="stSidebar"] { background: #171f1c; border-right: 1px solid #2a3731; }
[data-testid="stMetric"] { background: #18211d; border: 1px solid #2a3731; padding: 16px 18px; border-radius: 6px; }
[data-testid="stMetricLabel"] { color: #a6b5ad; }
code, [data-testid="stCode"] { font-family: 'DM Mono', monospace; }
h1, h2, h3 { letter-spacing: 0 !important; }
div.stButton > button[kind="primary"] { background: #b9e769; color: #152017; border: 0; font-weight: 700; }
div.stButton > button[kind="primary"]:hover { background: #c9f47b; color: #152017; }
</style>
""", unsafe_allow_html=True)

st.markdown("### ◉ LOGWATCH  /  SECURITY ANALYSIS")
st.title("Análisis de actividad")
st.caption("El análisis es local. La reputación externa solo se consulta cuando la solicitas, enviando IPs públicas a AbuseIPDB.")

with st.sidebar:
    st.markdown("## Parámetros de detección")
    umbral_bf = st.number_input("Fallos para fuerza bruta", min_value=2, max_value=100, value=5)
    ventana_tiempo = st.number_input("Ventana de tiempo (segundos)", min_value=1, max_value=3600, value=60)
    umbral_scan = st.number_input("Puertos de destino distintos", min_value=2, max_value=100, value=5)
    umbral_web = st.number_input("Rutas 404 distintas", min_value=2, max_value=500, value=10)
    analizar = st.button("Analizar logs", type="primary", use_container_width=True)
    st.caption("Formato admitido: syslog/auth.log, Apache o Nginx, firewall y texto plano. También admite .gz.")

subir, pegar = st.tabs(["Subir archivo", "Pegar contenido"])
with subir:
    archivo = st.file_uploader("Selecciona uno o varios logs", type=["log", "txt", "out", "gz"], accept_multiple_files=True)
with pegar:
    texto = st.text_area("Contenido del log", height=220, placeholder="Pega aquí las líneas que quieras analizar.")

if analizar:
    fuentes = []
    try:
        for carga in archivo or []:
            fuentes.append((carga.name, leer_logs_subidos(carga.getvalue(), carga.name)))
        if texto.strip():
            fuentes.append(("contenido pegado", texto.splitlines()))
        if not fuentes:
            st.error("Selecciona al menos un archivo o pega contenido antes de iniciar el análisis.")
        else:
            resultados = []
            with st.spinner("Leyendo y analizando las fuentes seleccionadas…"):
                for nombre, lineas in fuentes:
                    stats = analizar_logs(lineas, int(umbral_bf), int(ventana_tiempo), int(umbral_scan), int(umbral_web))
                    resultados.append({"fuente": nombre, "stats": stats})
            for clave in list(st.session_state):
                if clave.startswith("reputacion_"):
                    del st.session_state[clave]
            st.session_state.resultados = resultados
    except (OSError, EOFError, ValueError) as error:
        st.error(f"No se pudo leer el archivo: {error}")

for indice_resultado, resultado in enumerate(st.session_state.get("resultados", [])):
    stats = resultado["stats"]
    with st.container():
        st.markdown(f"#### {resultado['fuente']}")
        total_alertas = len(stats["ips_sospechosas_bf"] | stats["ips_sospechosas_scan"] | stats["ips_sospechosas_web"])
        cols = st.columns(4)
        cols[0].metric("Líneas leídas", f"{stats['total_lineas']:,}")
        cols[1].metric("IPs de origen", f"{len(stats['eventos_por_ip']):,}")
        cols[2].metric("Líneas con IP", f"{stats['lineas_reconocidas']:,}")
        cols[3].metric("IPs con alertas", f"{total_alertas:,}")

        clave_reputacion = f"reputacion_{indice_resultado}"
        if st.button("Consultar reputación externa", key=f"consultar_reputacion_{indice_resultado}"):
            api_key = os.getenv("ABUSEIPDB_API_KEY", "")
            if not api_key:
                st.warning("Configura ABUSEIPDB_API_KEY y reinicia Streamlit para activar esta consulta.")
            else:
                ips_alertadas = stats["ips_sospechosas_bf"] | stats["ips_sospechosas_scan"] | stats["ips_sospechosas_web"]
                ips_prioritarias = sorted(ips_alertadas)
                ips_prioritarias.extend(ip for ip in sorted(stats["eventos_por_ip"]) if ip not in ips_alertadas)
                try:
                    with st.spinner("Consultando hasta 20 IPs públicas en AbuseIPDB…"):
                        st.session_state[clave_reputacion] = consultar_ips_publicas(ips_prioritarias, api_key)
                except ValueError as error:
                    st.error(str(error))

        reputacion = st.session_state.get(clave_reputacion)
        if reputacion:
            st.caption(
                f"IPs públicas: {reputacion['ips_publicas']} · "
                f"No públicas omitidas: {reputacion['omitidas_no_publicas']} · "
                f"Fuera del límite de consulta: {reputacion['omitidas_por_limite']}"
            )
            filas_reputacion = []
            ips_con_score_alto = []
            for dato in reputacion["resultados"]:
                if "error" in dato:
                    filas_reputacion.append({"IP": dato["ip"], "Resultado": dato["error"], "Score": "-", "Reportes": "-", "Último reporte": "-", "País": "-", "Proveedor": "-"})
                    continue
                score = dato["score"]
                if score >= 75:
                    estado = "Abuso reportado alto"
                    ips_con_score_alto.append(dato["ip"])
                elif dato["reportes"]:
                    estado = "Con reportes recientes"
                else:
                    estado = "Sin reportes recientes"
                filas_reputacion.append({"IP": dato["ip"], "Resultado": estado, "Score": score, "Reportes": dato["reportes"], "Último reporte": dato["ultimo_reporte"], "País": dato["pais"], "Proveedor": dato["isp"]})
            st.dataframe(pd.DataFrame(filas_reputacion), use_container_width=True, hide_index=True)
            st.caption("El score refleja reportes de terceros en el periodo consultado; un score bajo no demuestra que una IP sea segura.")
            if ips_con_score_alto:
                st.warning("Revisa estas IPs antes de bloquearlas. Las reglas descargadas no se aplican automáticamente y requieren permisos de administrador.")
                plataforma = st.selectbox(
                    "Formato de reglas",
                    ["Windows Defender Firewall (PowerShell)", "Linux UFW"],
                    key=f"plataforma_bloqueo_{indice_resultado}",
                )
                reglas, nombre_reglas = generar_reglas_bloqueo(ips_con_score_alto, plataforma)
                st.download_button(
                    "Descargar reglas sugeridas",
                    reglas,
                    file_name=nombre_reglas,
                    mime="text/plain",
                    key=f"descargar_reglas_{indice_resultado}",
                )
            elif reputacion["resultados"]:
                st.info("Ninguna IP consultada superó el umbral de score 75 para sugerir reglas de bloqueo.")

        brute, ports, web, inventory = st.tabs(["Fuerza bruta", "Puertos", "Actividad web", "Inventario"])
        with brute:
            rows = [{"IP de origen": ip, "Fallos": stats["eventos_por_ip"][ip]["failed"]} for ip in sorted(stats["ips_sospechosas_bf"])]
            st.dataframe(pd.DataFrame(rows, columns=["IP de origen", "Fallos"]), use_container_width=True, hide_index=True)
            if not rows:
                st.info("No se superó el umbral de fallos de autenticación.")
        with ports:
            rows = [{"IP de origen": ip, "Puertos de destino": ", ".join(map(str, sorted(stats["puertos_por_ip"][ip]))), "Cantidad": len(stats["puertos_por_ip"][ip])} for ip in sorted(stats["ips_sospechosas_scan"])]
            st.dataframe(pd.DataFrame(rows, columns=["IP de origen", "Puertos de destino", "Cantidad"]), use_container_width=True, hide_index=True)
            if not rows:
                st.info("No se detectó actividad en múltiples puertos de destino.")
        with web:
            rows = [{"IP de origen": ip, "Errores HTTP": stats["errores_web_por_ip"][ip], "Rutas 404 distintas": len(stats["rutas_404_por_ip"][ip])} for ip in sorted(set(stats["errores_web_por_ip"]) | stats["ips_sospechosas_web"])]
            st.dataframe(pd.DataFrame(rows, columns=["IP de origen", "Errores HTTP", "Rutas 404 distintas"]), use_container_width=True, hide_index=True)
            if not rows:
                st.info("No se encontraron respuestas HTTP 4xx/5xx.")
        with inventory:
            rows = []
            for ip, eventos in sorted(stats["eventos_por_ip"].items(), key=lambda item: sum(item[1].values()), reverse=True):
                rows.append({"IP": ip, "Eventos": sum(eventos.values()), "Fallos": eventos["failed"], "Accesos": eventos["accepted"], "Errores web": eventos["web_error"], "Firewall": eventos["port_scan"]})
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        if stats["total_lineas"] > stats["lineas_reconocidas"]:
            st.caption(f"{stats['total_lineas'] - stats['lineas_reconocidas']:,} líneas no contenían una IP reconocible y no se atribuyeron a un origen.")