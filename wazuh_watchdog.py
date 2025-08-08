#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import shutil
import os
import sys
import yaml
import re
from dotenv import load_dotenv
import socket
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime, timezone, timedelta

# IMPORTACIONES PARA SMTP
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr

# Deshabilitar advertencias de certificados SSL auto-firmados (común en Wazuh)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

load_dotenv()

# --- Definiciones Globales de Configuración ---
CONFIG = {}
SENDER_DISPLAY_NAME = "Monitor Wazuh"
SENDER_EMAIL = ""
RECIPIENT_EMAILS = []
WAZUH_SERVICES = []
DISK_MONITOR_TARGETS = []
LOG_LEVEL = "INFO"
CONFIG_FILE_PATH = "/opt/wazuh_watchdog/config.yml"

# GLOBALES SMTP
SMTP_HOST, SMTP_PORT, SMTP_USE_TLS, SMTP_USE_SSL, SMTP_USERNAME, SMTP_PASSWORD = "", 0, False, False, "", ""

# GLOBALES PARA EL INDEXER
INDEXER_CHECK_ENABLED = False
INDEXER_IP = ""
INDEXER_PORT = 9200
INDEXER_USERNAME = ""
INDEXER_PASSWORD = ""
INDEXER_MINUTES_THRESHOLD = 0
INDEXER_INDICES_PATTERN = ""

# --- Nueva Función de Registro ---
def log_message(message, level="INFO"):
    """Imprime un mensaje de registro con timestamp y nivel de verbosidad."""
    # Asignar valores numéricos a los niveles de registro para la comparación
    level_map = {"DEBUG": 1, "INFO": 2, "ALERTA": 3, "FALLA": 3, "ERROR": 4, "CRITICAL": 5}
    
    # Obtener el valor numérico del nivel de registro global del script
    global_level_num = level_map.get(LOG_LEVEL, 2)
    # Obtener el valor numérico del nivel de este mensaje
    message_level_num = level_map.get(level.upper(), 2)

    # Solo imprimir si el nivel del mensaje es igual o más importante que el nivel global
    if message_level_num >= global_level_num:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefix = ""
        # Añadir un prefijo para los niveles que no son INFO o DEBUG
        if message_level_num > level_map["INFO"]:
            prefix = f"[{level.upper()}] "
        
        print(f"{timestamp} - {prefix}{message}")

# --- Carga y Aplicación de Configuración ---
def load_config(file_path):
    """Carga el archivo de configuración YAML."""
    log_message(f"Intentando cargar configuración de la aplicación desde: {file_path}", "DEBUG")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        if not config_data:
            log_message(f"El archivo '{file_path}' está vacío.", "CRITICAL")
            sys.exit(1)
        log_message("Archivo de configuración YAML cargado.", "DEBUG")
        return config_data
    except FileNotFoundError:
        log_message(f"Archivo '{file_path}' no encontrado.", "CRITICAL")
        sys.exit(1)
    except yaml.YAMLError as e:
        log_message(f"Error parseando YAML '{file_path}': {e}", "CRITICAL")
        sys.exit(1)
    except Exception as e:
        log_message(f"Error cargando '{file_path}': {e}", "CRITICAL")
        sys.exit(1)

def is_valid_email(email):
    """Valida si una cadena de texto es un email válido."""
    if not isinstance(email, str):
        return False
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

def apply_config(loaded_config):
    """Aplica la configuración cargada a las variables globales."""
    global CONFIG, SENDER_EMAIL, RECIPIENT_EMAILS, WAZUH_SERVICES, DISK_MONITOR_TARGETS, LOG_LEVEL, \
           SMTP_HOST, SMTP_PORT, SMTP_USE_TLS, SMTP_USE_SSL, SMTP_USERNAME, SMTP_PASSWORD, SENDER_DISPLAY_NAME, \
           INDEXER_CHECK_ENABLED, INDEXER_IP, INDEXER_PORT, INDEXER_USERNAME, INDEXER_PASSWORD, \
           INDEXER_MINUTES_THRESHOLD, INDEXER_INDICES_PATTERN
    
    CONFIG = loaded_config

    # Configuración Global - Se establece primero para que los logs funcionen desde el inicio
    global_cfg = CONFIG.get('global_settings', {})
    LOG_LEVEL = global_cfg.get('log_level', "INFO").upper()

    # Configuración de Email (SMTP)
    email_cfg_main = CONFIG.get('email_settings', {})
    smtp_config = email_cfg_main.get('smtp')
    if not smtp_config or not isinstance(smtp_config, dict):
        log_message("La sección 'email_settings.smtp' falta o no es válida en config.yml.", "CRITICAL")
        sys.exit(1)
    
    SMTP_HOST = smtp_config.get('host')
    SMTP_PORT = smtp_config.get('port')
    SMTP_USE_TLS = smtp_config.get('use_tls', False)
    SMTP_USE_SSL = smtp_config.get('use_ssl', False)
    SENDER_EMAIL = smtp_config.get('sender_email')
    SENDER_DISPLAY_NAME = smtp_config.get('sender_display_name', "Monitor Wazuh")
    
    SMTP_USERNAME = os.getenv('SMTP_USERNAME')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

    if not all([SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SENDER_EMAIL]):
        log_message("Faltan 'host', 'port', 'sender_email' en 'email_settings.smtp' o faltan SMTP_USERNAME/SMTP_PASSWORD en el archivo .env.", "CRITICAL")
        sys.exit(1)
    try:
        SMTP_PORT = int(SMTP_PORT)
    except (ValueError, TypeError):
        log_message(f"El puerto SMTP '{SMTP_PORT}' debe ser un número.", "CRITICAL")
        sys.exit(1)

    # Cargar y validar los correos de los destinatarios
    RECIPIENT_EMAILS_CFG = smtp_config.get('recipient_emails')
    if not RECIPIENT_EMAILS_CFG:
        log_message("'recipient_emails' falta en la sección de 'smtp' del config.yml.", "CRITICAL")
        sys.exit(1)
    if isinstance(RECIPIENT_EMAILS_CFG, str):
        RECIPIENT_EMAILS_TMP = [RECIPIENT_EMAILS_CFG.strip()]
    elif isinstance(RECIPIENT_EMAILS_CFG, list):
        RECIPIENT_EMAILS_TMP = [str(r).strip() for r in RECIPIENT_EMAILS_CFG if str(r).strip()]
    else:
        log_message("'recipient_emails' debe ser una cadena de texto o una lista.", "CRITICAL")
        sys.exit(1)
    
    valid_recipients = [email for email in RECIPIENT_EMAILS_TMP if is_valid_email(email)]
    if not valid_recipients:
        log_message("No se encontraron destinatarios de correo electrónico válidos en la configuración.", "CRITICAL")
        sys.exit(1)
    RECIPIENT_EMAILS = valid_recipients

    # Configuración de Monitoreo de Wazuh
    wazuh_config = CONFIG.get('wazuh_monitoring', {})
    WAZUH_SERVICES = wazuh_config.get('services', [])

    # Configuración de Monitoreo de Disco
    disk_config_main = CONFIG.get('disk_monitoring', {})
    DISK_MONITOR_TARGETS = disk_config_main.get('monitored_paths', [])
    
    # Configuración de Monitoreo del Indexer
    indexer_cfg = CONFIG.get('indexer_monitoring', {})
    if indexer_cfg and indexer_cfg.get('enabled') is True:
        log_message("Configurando la revisión del Wazuh Indexer.", "DEBUG")
        INDEXER_CHECK_ENABLED = True
        INDEXER_IP = indexer_cfg.get('ip')
        INDEXER_PORT = indexer_cfg.get('port', 9200)
        INDEXER_MINUTES_THRESHOLD = indexer_cfg.get('minutes_threshold')
        INDEXER_INDICES_PATTERN = indexer_cfg.get('indices_pattern', 'wazuh-alerts-*')
        
        INDEXER_USERNAME = os.getenv('INDEXER_USERNAME')
        INDEXER_PASSWORD = os.getenv('INDEXER_PASSWORD')

        if not all([INDEXER_IP, INDEXER_USERNAME, INDEXER_PASSWORD, INDEXER_MINUTES_THRESHOLD]):
            log_message("Faltan 'ip', 'minutes_threshold' en config.yml o faltan INDEXER_USERNAME/INDEXER_PASSWORD en el archivo .env.", "CRITICAL")
            sys.exit(1)
        try:
            INDEXER_PORT = int(INDEXER_PORT)
            INDEXER_MINUTES_THRESHOLD = int(INDEXER_MINUTES_THRESHOLD)
            if INDEXER_MINUTES_THRESHOLD <= 0: raise ValueError
        except (ValueError, TypeError):
            log_message("'port' y 'minutes_threshold' deben ser números positivos.", "CRITICAL")
            sys.exit(1)
    else:
        log_message("La revisión del Wazuh Indexer está deshabilitada.", "DEBUG")
    
    log_message("Validación de configuración de aplicación completada.", "DEBUG")

# --- Funciones de Verificación ---

def check_wazuh_services():
    """Verifica el estado de los servicios de Wazuh definidos en la configuración."""
    failed_services = []
    active_services = []
    if not WAZUH_SERVICES:
        return [], []

    log_message(f"Verificando servicios de Wazuh: {', '.join(WAZUH_SERVICES)}", "DEBUG")
    for service in WAZUH_SERVICES:
        try:
            result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True, check=False)
            status = result.stdout.strip()
            if status == "active":
                log_message(f"Servicio '{service}' está activo.", "DEBUG")
                active_services.append(service)
            else:
                error_details = result.stderr.strip() if result.stderr else f"El servicio reportó '{status}'."
                log_message(f"Servicio '{service}' NO está activo (estado: {status}).", "FALLA")
                failed_services.append({"name": service, "status": status, "details": error_details})
        except Exception as e:
            log_message(f"Excepción verificando '{service}': {e}", "ERROR")
            failed_services.append({"name": service, "status": "exception", "details": str(e)})
    if not failed_services:
        log_message("Todos los servicios de Wazuh monitorizados están activos.", "DEBUG")
    return failed_services, active_services

def check_disk_space(path, threshold_percent):
    """Verifica el espacio libre en una ruta y lo compara con un umbral."""
    try:
        usage = shutil.disk_usage(path)
        free_percent = (usage.free / usage.total) * 100
        log_message(f"Ruta '{path}': Libre: {free_percent:.2f}%, Umbral: {threshold_percent}%", "DEBUG")
        
        is_below_threshold = free_percent < threshold_percent
        if is_below_threshold:
            log_message(f"Ruta '{path}': espacio libre ({free_percent:.2f}%) POR DEBAJO del umbral ({threshold_percent}%)", "ALERTA")
        else:
            log_message(f"Ruta '{path}': espacio libre ({free_percent:.2f}%) por encima del umbral ({threshold_percent}%)", "DEBUG")

        return free_percent, is_below_threshold
    except FileNotFoundError:
        log_message(f"Ruta '{path}' no encontrada.", "ERROR")
        return -1, True
    except Exception as e:
        log_message(f"Excepción verificando disco para '{path}': {e}", "ERROR")
        return -1, True

def check_indexer_activity():
    """Consulta el Wazuh Indexer para ver si ha recibido eventos recientemente."""
    if not INDEXER_CHECK_ENABLED:
        return None

    log_message(f"Verificando actividad del Wazuh Indexer ({INDEXER_IP}:{INDEXER_PORT})", "DEBUG")
    
    url = f"https://{INDEXER_IP}:{INDEXER_PORT}/{INDEXER_INDICES_PATTERN}/_count"
    now_utc = datetime.now(timezone.utc)
    time_ago = now_utc - timedelta(minutes=INDEXER_MINUTES_THRESHOLD)
    
    query_time_format = "%Y-%m-%dT%H:%M:%S.%f"
    now_str = now_utc.strftime(query_time_format)[:-3] + "Z"
    time_ago_str = time_ago.strftime(query_time_format)[:-3] + "Z"

    query = {"query": {"range": {"@timestamp": {"gte": time_ago_str, "lt": now_str}}}}

    try:
        response = requests.post(
            url,
            auth=HTTPBasicAuth(INDEXER_USERNAME, INDEXER_PASSWORD),
            json=query,
            verify=False,
            timeout=15
        )
        if response.status_code == 200:
            event_count = response.json().get("count", 0)
            if event_count == 0:
                msg = f"No se han recibido eventos en los últimos {INDEXER_MINUTES_THRESHOLD} minutos."
                log_message(msg, "ALERTA")
                return {"error": True, "message": msg}
            else:
                log_message(f"Se encontraron {event_count} eventos en los últimos {INDEXER_MINUTES_THRESHOLD} minutos.", "DEBUG")
                return None
        else:
            msg = f"Error al consultar la API del Indexer. Código: {response.status_code}. Respuesta: {response.text}"
            log_message(msg, "ERROR")
            return {"error": True, "message": msg}
    except requests.exceptions.RequestException as e:
        msg = f"No se pudo conectar al Wazuh Indexer en {INDEXER_IP}:{INDEXER_PORT}. Error: {e}"
        log_message(msg, "ERROR")
        return {"error": True, "message": msg}

# --- Función de Envío de Correo ---
def send_smtp_email(subject_str, body_html):
    """Envía un correo electrónico usando SMTP."""
    if not RECIPIENT_EMAILS:
        log_message("No hay destinatarios definidos para enviar el correo.", "ERROR")
        return False

    msg = MIMEMultipart('alternative')
    msg['Subject'] = Header(subject_str, 'utf-8').encode()
    msg['From'] = formataddr((str(Header(SENDER_DISPLAY_NAME, 'utf-8')), SENDER_EMAIL))
    msg['To'] = ", ".join(RECIPIENT_EMAILS)
    msg.attach(MIMEText(body_html, 'html', 'utf-8'))
    
    server = None
    try:
        if SMTP_USE_SSL:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
            if SMTP_USE_TLS:
                server.starttls()
        
        if LOG_LEVEL == "DEBUG":
            server.set_debuglevel(1)
        
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAILS, msg.as_string())
        log_message(f"Correo enviado vía SMTP a: {', '.join(RECIPIENT_EMAILS)}")
        return True
    except Exception as e:
        log_message(f"Falló el envío de correo: {e}", "ERROR")
        return False
    finally:
        if server:
            server.quit()

# --- Lógica Principal ---
def main_logic():
    log_message("--- Iniciando Script de Verificación ---")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
    
    try:
        hostname = socket.gethostname()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        server_ip = s.getsockname()[0]
        s.close()
    except Exception:
        hostname = os.uname().nodename if hasattr(os, 'uname') else socket.gethostname()
        server_ip = "IP no encontrada"

    # --- Realizar todas las verificaciones ---
    failed_wazuh_services, active_wazuh_services = check_wazuh_services()
    
    disk_space_alerts_details = []
    any_disk_alert_triggered = False
    if DISK_MONITOR_TARGETS:
        log_message(f"Verificando Espacio en Disco para {len(DISK_MONITOR_TARGETS)} ruta(s)", "DEBUG")
        for target in DISK_MONITOR_TARGETS:
            path = target.get('path')
            threshold_str = target.get('threshold_percentage')
            if path and threshold_str is not None:
                try:
                    threshold = int(threshold_str)
                    free_percent, alert_triggered = check_disk_space(path, threshold)
                    if alert_triggered:
                        any_disk_alert_triggered = True
                        msg = "Error crítico verificando espacio." if free_percent == -1 else f"Espacio libre <b>{free_percent:.2f}%</b> < umbral <b>{threshold}%</b>."
                        disk_space_alerts_details.append({'path': path, 'message': msg})
                except (ValueError, TypeError):
                    log_message(f"El umbral '{threshold_str}' para la ruta '{path}' no es un número válido.", "ERROR")
    
    indexer_alert = check_indexer_activity()

    # --- Evaluar resultados y enviar alerta ---
    issues_found = failed_wazuh_services or any_disk_alert_triggered or indexer_alert

    if not issues_found:
        log_message("--- No se detectaron problemas. Todo OK. ---")
        log_message("--- Script de Verificación Finalizado ---")
        return

    log_message("--- Se detectaron problemas. Preparando correo de alerta. ---")
    
    server_identifier = f"{hostname} ({server_ip})"
    email_subject = f"⚠️ Alerta de Salud Servidor Wazuh: {server_identifier}"
    
    alert_messages_html = []
    if indexer_alert:
        safe_message = indexer_alert['message'].replace('<', '&lt;').replace('>', '&gt;')
        alert_messages_html.append(f"<h2>🚨 Alerta del Indexer de Wazuh</h2><ul><li><b>Problema:</b><br><pre>{safe_message}</pre></li></ul>")
    
    if failed_wazuh_services:
        alert_messages_html.append("<h2>❌ Fallos en Servicios de Wazuh</h2><ul>")
        for s in failed_wazuh_services:
            details = s['details'].replace('<', '&lt;').replace('>', '&gt;')
            alert_messages_html.append(f"<li><b>{s['name']}</b>: {s['status']} <pre>{details}</pre></li>")
        alert_messages_html.append("</ul>")

    if any_disk_alert_triggered:
        alert_messages_html.append("<h2>⚠️ Alertas de Espacio en Disco</h2><ul>")
        for a in disk_space_alerts_details:
            alert_messages_html.append(f"<li><b>Ruta: {a['path']}</b><br>{a['message']}</li>")
        alert_messages_html.append("</ul>")

    # Construcción del cuerpo del HTML
    body_html_parts = [
        f"<html><head><style>"
        f"body {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; color: #333; }}"
        f".container {{ max-width: 600px; margin: 20px auto; background-color: #ffffff; border: 1px solid #dddddd; border-radius: 8px; }}"
        f".header {{ background-color: #d9534f; color: white; padding: 20px; text-align: center; border-top-left-radius: 8px; border-top-right-radius: 8px; }}"
        f".content {{ padding: 20px; line-height: 1.6; }}"
        f"h1 {{ font-size: 24px; margin-top:0; }}"
        f"h2 {{ font-size: 20px; color: #c9302c; border-bottom: 1px solid #eeeeee; padding-bottom: 10px; }}"
        f"ul {{ list-style-type: none; padding-left: 0; }}"
        f"li {{ background-color: #f9f9f9; border: 1px solid #ddd; margin-bottom: 10px; padding: 15px; border-radius: 4px; }}"
        f"pre {{ background-color: #eeeeee; padding: 10px; border-radius: 3px; white-space: pre-wrap; word-wrap: break-word; font-size: 0.9em; border: 1px solid #ccc;}}"
        f".footer {{ text-align: center; padding: 15px; font-size: 0.8em; color: #aaaaaa; }}"
        f"</style></head><body>"
        f"<div class='container'>"
        f"<div class='header'><h1>Informe de Alerta del Servidor Wazuh</h1></div>"
        f"<div class='content'>"
        f"<p><strong>Servidor:</strong> {server_identifier}<br>"
        f"<strong>Fecha y Hora del Reporte:</strong> {timestamp}</p><hr>",
        "".join(alert_messages_html),
        f"</div><div class='footer'>Este es un mensaje automatizado.</div></div></body></html>"
    ]
    email_body = "".join(body_html_parts)
    
    send_smtp_email(email_subject, email_body)

    log_message("--- Script de Verificación Finalizado ---")


# --- Punto de Entrada ---
if __name__ == "__main__":
    try:
        # Cargar la configuración primero para establecer el LOG_LEVEL
        loaded_config_data = load_config(CONFIG_FILE_PATH)
        apply_config(loaded_config_data)
        main_logic()
    except SystemExit as e:
        log_message(f"El script ha terminado de forma controlada con código de salida {e.code}.", "INFO")
    except Exception as e:
        log_message(f"El script ha fallado por un error fatal no controlado: {e}", "CRITICAL")

