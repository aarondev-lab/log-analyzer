# Analizador de Logs de Seguridad

Este es un script en Python que analiza logs en busca de patrones de ataques (fuerza bruta y escaneo de puertos).  
Puede trabajar con logs reales o generar logs simulados para demostración.

Además, incluye una **versión web interactiva** creada con Streamlit para probarlo fácilmente desde el navegador.

## Características

- ✅ Detecta **fuerza bruta** (múltiples intentos fallidos desde misma IP en poco tiempo).
- ✅ Detecta **escaneo de puertos** (conexiones a múltiples puertos desde misma IP).
- ✅ Barra de progreso interactiva con `tqdm` (versión terminal).
- ✅ Genera logs de ejemplo realistas si no se proporciona un archivo.
- ✅ Informe detallado con IPs sospechosas en consola y HTML.
- ✅ **Versión web** con Streamlit: configuración interactiva y visualización de resultados.

# 📸 Demo

![Demo del analizador de logs](assets/demo.gif)

## Instalación del proyecto (OpenSource)

# 1. Clonar el repositorio
```bash
git clone https://github.com/aarondev-lab/log-analyzer.git
cd log-analyzer

# 2. Instalación dependencias con requirements
pip install -r requirements.txt

### 3. Inicialización del script
python/python3 analyzer.py

python analyzer.py -n 500 ("especifíca el n de líneas")

### 4. Demo interactiva con streamlit
python -m streamlit run app.py