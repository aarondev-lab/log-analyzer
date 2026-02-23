# app.py
import streamlit as st
import pandas as pd
import time
from utils.analizador import generar_logs_simulados, analizar_logs

st.set_page_config(
    page_title="Analizador de Logs",
    layout="wide"
)

st.title(" Analizador de Logs de Seguridad")
st.markdown("""
Esta herramienta analiza logs de servidor para detectar patrones de ataque:
- **Fuerza bruta**: múltiples intentos fallidos desde una misma IP
- **Escaneo de puertos**: conexiones a múltiples puertos desde una misma IP
""")

with st.sidebar:
    st.header("⚙️ Configuración")
    num_lineas = st.slider(
        "Número de líneas a generar",
        min_value=50,
        max_value=500,
        value=200,
        step=50
    )
    umbral_bf = st.number_input(
        "Umbral de fuerza bruta (intentos)",
        min_value=3,
        max_value=20,
        value=5
    )
    umbral_scan = st.number_input(
        "Umbral de escaneo (puertos)",
        min_value=3,
        max_value=20,
        value=5
    )
    ventana_tiempo = st.number_input(
        "Ventana de tiempo (segundos)",
        min_value=10,
        max_value=300,
        value=60
    )
    if st.button("Ejecutar Análisis", type="primary"):
        st.session_state.ejecutar = True
    else:
        if 'ejecutar' not in st.session_state:
            st.session_state.ejecutar = False

if st.session_state.ejecutar:
    with st.spinner("Generando logs simulados..."):
        progress_bar = st.progress(0)
        status_text = st.empty()
        status_text.text("Generando logs...")
        for i in range(10):
            time.sleep(0.1)
            progress_bar.progress((i + 1) * 10)
        lineas = generar_logs_simulados(num_lineas)
        progress_bar.progress(100)
        status_text.text("Logs generados..")
        time.sleep(0.5)
        status_text.text("Analizando logs...")
        progress_bar.progress(0)
        for i in range(10):
            time.sleep(0.1)
            progress_bar.progress((i + 1) * 10)
        stats = analizar_logs(
            lineas,
            umbral_bf=umbral_bf,
            ventana_tiempo=ventana_tiempo,
            umbral_scan=umbral_scan
        )
        progress_bar.progress(100)
        status_text.text("Análisis completado..")
        time.sleep(0.5)
        progress_bar.empty()
        status_text.empty()

    st.success(f"Análisis completado: {stats['total_lineas']} líneas procesadas")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Líneas totales", stats['total_lineas'])
    with col2:
        st.metric("IPs únicas", len(stats['eventos_por_ip']))
    with col3:
        total_alertas = len(stats['ips_sospechosas_bf']) + len(stats['ips_sospechosas_scan'])
        st.metric("⚠️ Alertas", total_alertas)

    with st.expander("IPs sospechosas de fuerza bruta", expanded=True):
        if stats['ips_sospechosas_bf']:
            data_bf = []
            for ip in sorted(stats['ips_sospechosas_bf']):
                data_bf.append({
                    "IP": ip,
                    "Intentos fallidos": stats['eventos_por_ip'][ip]['failed'],
                    "Eventos totales": sum(stats['eventos_por_ip'][ip].values())
                })
            df_bf = pd.DataFrame(data_bf)
            st.dataframe(df_bf, use_container_width=True)
        else:
            st.info("No se detectaron ataques de fuerza bruta.")

    with st.expander("IPs sospechosas de escaneo de puertos", expanded=True):
        if stats['ips_sospechosas_scan']:
            data_scan = []
            for ip in sorted(stats['ips_sospechosas_scan']):
                data_scan.append({
                    "IP": ip,
                    "Puertos": ', '.join(map(str, sorted(stats['puertos_por_ip'][ip]))),
                    "Total puertos": len(stats['puertos_por_ip'][ip])
                })
            df_scan = pd.DataFrame(data_scan)
            st.dataframe(df_scan, use_container_width=True)
        else:
            st.info("No se detectaron escaneos de puertos.")

    with st.expander("📈 Top 5 IPs más activas"):
        top_ips = sorted(
            stats['eventos_por_ip'].items(),
            key=lambda x: sum(x[1].values()),
            reverse=True
        )[:5]
        data_top = []
        for ip, eventos in top_ips:
            data_top.append({
                "IP": ip,
                "Total": sum(eventos.values()),
                "Fallidos": eventos['failed'],
                "Exitosos": eventos['accepted'],
                "Escaneo": eventos['port_scan'],
                "Otros": eventos['other']
            })
        df_top = pd.DataFrame(data_top)
        st.dataframe(df_top, use_container_width=True)

    if st.button("🔄 Nuevo análisis"):
        st.session_state.ejecutar = False
        st.rerun()
else:
    st.info("Configura los parámetros en la barra lateral y haz clic en 'Ejecutar Análisis' para comenzar")
    with st.expander("ℹ️ ¿Cómo funciona?"):
        st.markdown("""
        1. **Genera logs simulados** con patrones de tráfico normales y maliciosos
        2. **Analiza cada línea** extrayendo IPs, eventos y puertos
        3. **Detecta fuerza bruta** buscando múltiples intentos fallidos en poco tiempo
        4. **Detecta escaneos** identificando IPs que conectan a muchos puertos distintos
        5. **Muestra resultados** en tablas interactivas
        """)