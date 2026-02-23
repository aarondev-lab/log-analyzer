# Analizador de Logs de Seguridad

Este es un script en Python que analiza logs en busca de patrones de ataques (fuerza bruta y escaneo de puertos).  
Puede trabajar con logs reales o incluso generar logs simulados para una demostración de su uso.

## Características

- ✅ Detecta **fuerza bruta** (múltiples intentos fallidos desde misma IP en poco tiempo).
- ✅ Detecta **escaneo de puertos** (conexiones a múltiples puertos desde misma IP).
- ✅ Barra de progreso interactiva con `tqdm`.
- ✅ Genera logs de ejemplo realistas si no se proporciona un archivo.
- ✅ Informe detallado con IPs sospechosas.

## Uso

### 1. Clonar el repositorio

### 2. Instalación dependencias con requirements.txt
pip install -r requirements.txt

pip install jinja2 (genera el reporte para los logs analizados)

### 3. Ejecución del script
python/python3 analyzer.py (python depende de la versión del usuario)

python/python3 analyzer.py -n 500 (genera un análisis de un total de n líneas)

```bash
git clone https://github.com/aarondev-lab/log-analyzer.git
cd log-analyzer

## 📸 Demo

![Demo del analizador de logs](assets/demo.gif)