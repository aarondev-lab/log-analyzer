# Analizador de logs

Hice este proyecto para revisar logs de servidores sin tener que ir línea por línea. Se puede usar desde la terminal o desde una interfaz web con Streamlit. El análisis se hace sobre el archivo que le pases; no crea logs de prueba por su cuenta.

## Qué revisa

- Intentos fallidos de acceso repetidos desde una misma IP, tanto en logs SSH como en respuestas web HTTP 401.
- Puertos de destino distintos en registros de firewall.
- Muchas rutas diferentes que responden con HTTP 404, algo que puede indicar que están buscando archivos o páginas en el servidor.
- IPs con más actividad y errores HTTP.

El parser reconoce fechas ISO, syslog y formatos habituales de Apache/Nginx. También acepta IPv4, IPv6 y archivos comprimidos `.gz`. Para detectar escaneos de puertos hace falta que el log indique el puerto de destino; el puerto de origen de una conexión SSH no cuenta como escaneo.

## Instalación

Desde la carpeta del proyecto, crea un entorno e instala las dependencias:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Usarlo desde la terminal

Pasa la ruta del log que quieras revisar:

```powershell
python analyzer.py "C:\ruta\al\archivo.log"
python analyzer.py "C:\ruta\al\archivo.log" --umbral-bf 6 --ventana 90
python analyzer.py "C:\ruta\al\access.log" --html reporte.html
```

También puedes analizar logs `.gz`. Para ajustar las detecciones están `--umbral-bf`, `--ventana`, `--umbral-scan` y `--umbral-web`. Si usas `--html`, se genera un informe que puedes abrir con `--abrir-html`. Rich se encarga de mostrar las tablas y el resumen con formato en la terminal.

## Usarlo con Streamlit

```powershell
python -m streamlit run app.py
```

En la página puedes subir uno o varios archivos, o pegar el contenido directamente. Si ejecutas Streamlit en otro equipo o servidor, los archivos se procesan allí. La consulta de reputación externa es opcional y solo se realiza cuando la solicitas.

### Consultar reputación y preparar bloqueos

La consulta externa es opcional. En la barra lateral puedes elegir VirusTotal o AbuseIPDB y pegar la clave correspondiente en el campo protegido. También puedes guardar la clave de VirusTotal en PowerShell antes de iniciar Streamlit:

```powershell
$env:VIRUSTOTAL_API_KEY = "tu_clave_de_VirusTotal"
python -m streamlit run app.py
```

Con VirusTotal, la tabla muestra detecciones maliciosas sobre el total de motores (por ejemplo, `16/91`), sospechosos y fecha del análisis. El plan público permite 4 consultas por minuto y 500 al día, y no se permite usarlo en productos comerciales. VirusTotal indica que los indicadores consultados se incorporan a su conjunto de datos; marca la casilla de consentimiento antes de consultar. Solo se envían IPs públicas, nunca las líneas del log.

AbuseIPDB muestra su propia puntuación de confianza y número de reportes. Esa puntuación no es comparable con el ratio de detecciones de VirusTotal.

Si VirusTotal marca al menos 5 motores como maliciosos o AbuseIPDB da una puntuación de 75 o más, puedes descargar reglas para Windows Defender Firewall o Linux UFW. La aplicación no las ejecuta: revísalas primero y aplícalas manualmente con permisos de administrador. Una regla incorrecta puede bloquear tráfico legítimo.

## A tener en cuenta

Los formatos de log cambian bastante según el sistema y la configuración. Las líneas que no reconoce se cuentan, pero no se usan para crear alertas. Los resultados sirven como indicios para revisar, no como confirmación de que haya ocurrido un ataque.
