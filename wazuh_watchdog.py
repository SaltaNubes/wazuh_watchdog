#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import shutil
import os
import sys
import yaml
import re
import json
import time
import socket
import requests
import smtplib
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr

# Deshabilitar advertencias de certificados SSL auto-firmados
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- CARGA SEGURA DEL .ENV ---
# Esto asegura que encuentre el .env en la misma carpeta del script, incluso si se ejecuta por CRON
script_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(script_dir, '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    print(f"ADVERTENCIA: No se encontró el archivo .env en: {env_path}")

# --- Definiciones Globales ---
CONFIG = {}
SENDER_DISPLAY_NAME = "Monitor Wazuh"
SENDER_EMAIL = ""
RECIPIENT_EMAILS = []
WAZUH_SERVICES = []
DISK_MONITOR_TARGETS = []
LOG_LEVEL = "INFO"

# Rutas de archivos
CONFIG_FILE_PATH = "/opt/wazuh_watchdog/config.yml"
STATE_FILE_PATH = "/opt/wazuh_watchdog/email_state.json"

# Variables SMTP (Inicializadas como None para validación posterior)
SMTP_HOST = None
SMTP_PORT = None
SMTP_USE_TLS = False
SMTP_USE_SSL = False
SMTP_USERNAME = None
SMTP_PASSWORD = None

# Variables Rate Limit
EMAIL_LIMIT_ENABLED = False
EMAIL_LIMIT_MAX = 5
EMAIL_LIMIT_WINDOW_SECONDS = 3600

# Variables Indexer
INDEXER_CHECK_ENABLED = False
INDEXER_IP = None
INDEXER_PORT = 9200
INDEXER_USERNAME = None
INDEXER_PASSWORD = None
INDEXER_MINUTES_THRESHOLD = 0
INDEXER_INDICES_PATTERN = ""

# --- Función de Registro ---
def log_message(message, level="INFO"):
    """Imprime un mensaje de registro con timestamp y nivel de verbosidad."""
    level_map = {"DEBUG": 1, "INFO": 2, "ALERTA": 3, "FALLA": 3, "ERROR": 4, "CRITICAL": 5}
    
    global_level_num = level_map.get(LOG_LEVEL, 2)
    message_level_num = level_map.get(level.upper(), 2)

    if message_level_num >= global_level_num:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefix = ""
        if message_level_num > level_map["INFO"]:
            prefix = f"[{level.upper()}] "
        print(f"{timestamp} - {prefix}{message}")

# --- Carga de Configuración ---
def load_config(file_path):
    log_message(f"Cargando configuración desde: {file_path}", "DEBUG")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        if not config_data:
            log_message(f"El archivo '{file_path}' está vacío.", "CRITICAL")
            sys.exit(1)
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
    if not isinstance(email, str): return False
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

def apply_config(loaded_config):
    """Aplica configuración con validación estricta y mensajes de error detallados."""
    global CONFIG, SENDER_EMAIL, RECIPIENT_EMAILS, WAZUH_SERVICES, DISK_MONITOR_TARGETS, LOG_LEVEL, \
           SMTP_HOST, SMTP_PORT, SMTP_USE_TLS, SMTP_USE_SSL, SMTP_USERNAME, SMTP_PASSWORD, SENDER_DISPLAY_NAME, \
           INDEXER_CHECK_ENABLED, INDEXER_IP, INDEXER_PORT, INDEXER_USERNAME, INDEXER_PASSWORD, \
           INDEXER_MINUTES_THRESHOLD, INDEXER_INDICES_PATTERN, \
           EMAIL_LIMIT_ENABLED, EMAIL_LIMIT_MAX, EMAIL_LIMIT_WINDOW_SECONDS
    
    CONFIG = loaded_config
    global_cfg = CONFIG.get('global_settings', {})
    LOG_LEVEL = global_cfg.get('log_level', "INFO").upper()

    # --- 1. EMAIL & RATE LIMIT ---
    email_cfg_main = CONFIG.get('email_settings', {})
    smtp_config = email_cfg_main.get('smtp')
    
    if not smtp_config or not isinstance(smtp_config, dict):
        log_message("La sección 'email_settings.smtp' falta en config.yml.", "CRITICAL")
        sys.exit(1)
    
    rate_limit_cfg = email_cfg_main.get('rate_limit', {})
    EMAIL_LIMIT_ENABLED = rate_limit_cfg.get('enabled', False)
    if EMAIL_LIMIT_ENABLED:
        EMAIL_LIMIT_MAX = rate_limit_cfg.get('max_emails', 5)
        mins = rate_limit_cfg.get('interval_minutes', 60)
        EMAIL_LIMIT_WINDOW_SECONDS = mins * 60

    SMTP_HOST = smtp_config.get('host')
    SMTP_PORT = smtp_config.get('port')
    SMTP_USE_TLS = smtp_config.get('use_tls', False)
    SMTP_USE_SSL = smtp_config.get('use_ssl', False)
    SENDER_EMAIL = smtp_config.get('sender_email')
    SENDER_DISPLAY_NAME = smtp_config.get('sender_display_name', "Monitor Wazuh")
    
    # Carga desde .env
    SMTP_USERNAME = os.getenv('SMTP_USERNAME')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

    # AUDITORÍA DE CREDENCIALES SMTP
    missing_vars = []
    if not SMTP_HOST: missing_vars.append("host (config.yml)")
    if not SMTP_PORT: missing_vars.append("port (config.yml)")
    if not SENDER_EMAIL: missing_vars.append("sender_email (config.yml)")
    if not SMTP_USERNAME: missing_vars.append("SMTP_USERNAME (archivo .env)")
    if not SMTP_PASSWORD: missing_vars.append("SMTP_PASSWORD (archivo .env)")

    if missing_vars:
        log_message(f"❌ ERROR CRÍTICO SMTP. Faltan variables:\n -> " + "\n -> ".join(missing_vars), "CRITICAL")
        sys.exit(1)

    try:
        SMTP_PORT = int(SMTP_PORT)
    except (ValueError, TypeError):
        log_message(f"El puerto SMTP '{SMTP_PORT}' no es válido.", "CRITICAL")
        sys.exit(1)

    # Validar Destinatarios
    RECIPIENT_EMAILS_CFG = smtp_config.get('recipient_emails')
    if isinstance(RECIPIENT_EMAILS_CFG, str):
        RECIPIENT_EMAILS_TMP = [RECIPIENT_EMAILS_CFG.strip()]
    elif isinstance(RECIPIENT_EMAILS_CFG, list):
        RECIPIENT_EMAILS_TMP = [str(r).strip() for r in RECIPIENT_EMAILS_CFG if str(r).strip()]
    else:
        log_message("'recipient_emails' debe ser texto o lista.", "CRITICAL")
        sys.exit(1)
    
    RECIPIENT_EMAILS = [email for email in RECIPIENT_EMAILS_TMP if is_valid_email(email)]
    if not RECIPIENT_EMAILS:
        log_message("No se encontraron destinatarios de correo válidos.", "CRITICAL")
        sys.exit(1)

    # --- 2. WAZUH & DISK ---
    wazuh_config = CONFIG.get('wazuh_monitoring', {})
    WAZUH_SERVICES = wazuh_config.get('services', [])
    disk_config_main = CONFIG.get('disk_monitoring', {})
    DISK_MONITOR_TARGETS = disk_config_main.get('monitored_paths', [])
    
    # --- 3. INDEXER ---
    indexer_cfg = CONFIG.get('indexer_monitoring', {})
    if indexer_cfg and indexer_cfg.get('enabled') is True:
        INDEXER_CHECK_ENABLED = True
        INDEXER_IP = indexer_cfg.get('ip')
        INDEXER_PORT = indexer_cfg.get('port', 9200)
        INDEXER_MINUTES_THRESHOLD = indexer_cfg.get('minutes_threshold')
        INDEXER_INDICES_PATTERN = indexer_cfg.get('indices_pattern', 'wazuh-alerts-*')
        
        INDEXER_USERNAME = os.getenv('INDEXER_USERNAME')
        INDEXER_PASSWORD = os.getenv('INDEXER_PASSWORD')

        missing_indexer = []
        if not INDEXER_IP: missing_indexer.append("ip (config.yml)")
        if not INDEXER_MINUTES_THRESHOLD: missing_indexer.append("minutes_threshold (config.yml)")
        if not INDEXER_USERNAME: missing_indexer.append("INDEXER_USERNAME (.env)")
        if not INDEXER_PASSWORD: missing_indexer.append("INDEXER_PASSWORD (.env)")

        if missing_indexer:
            log_message(f"❌ ERROR CRÍTICO INDEXER. Faltan:\n -> " + "\n -> ".join(missing_indexer), "CRITICAL")
            sys.exit(1)

        try:
            INDEXER_PORT = int(INDEXER_PORT)
            INDEXER_MINUTES_THRESHOLD = int(INDEXER_MINUTES_THRESHOLD)
        except (ValueError, TypeError):
            log_message("Valores numéricos de Indexer inválidos.", "CRITICAL")
            sys.exit(1)
    
    log_message("✅ Configuración y credenciales validadas correctamente.", "DEBUG")

# --- Funciones de Verificación ---
def check_wazuh_services():
    failed, active = [], []
    if not WAZUH_SERVICES: return [], []

    log_message(f"Verificando servicios: {', '.join(WAZUH_SERVICES)}", "DEBUG")
    for service in WAZUH_SERVICES:
        try:
            result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True)
            status = result.stdout.strip()
            if status == "active":
                active.append(service)
            else:
                err = result.stderr.strip() if result.stderr else f"Estado: {status}"
                log_message(f"Servicio '{service}' INACTIVO.", "FALLA")
                failed.append({"name": service, "status": status, "details": err})
        except Exception as e:
            failed.append({"name": service, "status": "exception", "details": str(e)})
    return failed, active

def check_disk_space(path, threshold):
    try:
        usage = shutil.disk_usage(path)
        free_pct = (usage.free / usage.total) * 100
        below = free_pct < threshold
        if below:
            log_message(f"Disco '{path}': Libre {free_pct:.2f}% < Umbral {threshold}%", "ALERTA")
        return free_pct, below
    except Exception as e:
        log_message(f"Error disco '{path}': {e}", "ERROR")
        return -1, True

def check_indexer_activity():
    if not INDEXER_CHECK_ENABLED: return None
    
    url = f"https://{INDEXER_IP}:{INDEXER_PORT}/{INDEXER_INDICES_PATTERN}/_count"
    now_utc = datetime.now(timezone.utc)
    time_ago = now_utc - timedelta(minutes=INDEXER_MINUTES_THRESHOLD)
    
    fmt = "%Y-%m-%dT%H:%M:%S.%f"
    now_str = now_utc.strftime(fmt)[:-3] + "Z"
    ago_str = time_ago.strftime(fmt)[:-3] + "Z"
    query = {"query": {"range": {"@timestamp": {"gte": ago_str, "lt": now_str}}}}

    try:
        res = requests.post(url, auth=HTTPBasicAuth(INDEXER_USERNAME, INDEXER_PASSWORD),
                            json=query, verify=False, timeout=15)
        if res.status_code == 200:
            if res.json().get("count", 0) == 0:
                msg = f"Sin eventos en los últimos {INDEXER_MINUTES_THRESHOLD} min."
                log_message(msg, "ALERTA")
                return {"error": True, "message": msg}
            return None
        else:
            msg = f"Error API Indexer: {res.status_code} - {res.text}"
            log_message(msg, "ERROR")
            return {"error": True, "message": msg}
    except Exception as e:
        msg = f"Excepción Indexer: {e}"
        log_message(msg, "ERROR")
        return {"error": True, "message": msg}

# --- LÓGICA RATE LIMIT ---
def get_email_state():
    default = {"count": 0, "window_start": time.time()}
    if not os.path.exists(STATE_FILE_PATH): return default
    try:
        with open(STATE_FILE_PATH, 'r') as f: return json.load(f)
    except: return default

def save_email_state(state):
    try:
        with open(STATE_FILE_PATH, 'w') as f: json.dump(state, f)
    except Exception as e:
        log_message(f"Error guardando estado email: {e}", "ERROR")

def check_and_update_rate_limit():
    if not EMAIL_LIMIT_ENABLED: return True
    
    state = get_email_state()
    now = time.time()
    
    # Reiniciar ventana si expiró
    if now - state["window_start"] > EMAIL_LIMIT_WINDOW_SECONDS:
        log_message("Ventana de tiempo reiniciada para envío de correos.", "DEBUG")
        state["count"] = 0
        state["window_start"] = now

    if state["count"] >= EMAIL_LIMIT_MAX:
        log_message(f"🚫 Límite de correos alcanzado ({state['count']}/{EMAIL_LIMIT_MAX}). Alerta suprimida.", "ALERTA")
        save_email_state(state) # Guardar para mantener la ventana de tiempo
        return False

    state["count"] += 1
    save_email_state(state)
    log_message(f"📧 Enviando correo {state['count']} de {EMAIL_LIMIT_MAX} en esta ventana.", "DEBUG")
    return True

# --- ENVÍO DE CORREO ---
def send_smtp_email(subject, body):
    if not check_and_update_rate_limit(): return False
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = Header(subject, 'utf-8').encode()
    msg['From'] = formataddr((str(Header(SENDER_DISPLAY_NAME, 'utf-8')), SENDER_EMAIL))
    msg['To'] = ", ".join(RECIPIENT_EMAILS)
    msg.attach(MIMEText(body, 'html', 'utf-8'))
    
    server = None
    try:
        if SMTP_USE_SSL:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
            if SMTP_USE_TLS: server.starttls()
        
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAILS, msg.as_string())
        log_message(f"Correo enviado exitosamente a {len(RECIPIENT_EMAILS)} destinatarios.")
        return True
    except Exception as e:
        log_message(f"Falló envío SMTP: {e}", "ERROR")
        return False
    finally:
        if server: server.quit()

# --- ORQUESTACIÓN PRINCIPAL ---
def main_logic():
    log_message("--- Iniciando Diagnóstico ---")
    
    try:
        h = socket.gethostname()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except:
        h, ip = "Desconocido", "0.0.0.0"

    failed_services, _ = check_wazuh_services()
    
    disk_alerts = []
    any_disk_issue = False
    for t in DISK_MONITOR_TARGETS:
        p, th = t.get('path'), t.get('threshold_percentage')
        if p and th:
            fp, trig = check_disk_space(p, int(th))
            if trig:
                any_disk_issue = True
                msg = "Error acceso disco" if fp == -1 else f"Libre: <b>{fp:.2f}%</b> < Min: <b>{th}%</b>"
                disk_alerts.append({'path': p, 'msg': msg})

    indexer_issue = check_indexer_activity()

    if not (failed_services or any_disk_issue or indexer_issue):
        log_message("--- Sistema Saludable. Fin. ---")
        return

    log_message("--- Problemas detectados. Generando reporte. ---")
    
    # Construcción HTML
    html_alerts = []
    if indexer_issue:
        html_alerts.append(f"<h2>🚨 Indexer Wazuh</h2><p>{indexer_issue['message']}</p>")
    
    if failed_services:
        html_alerts.append("<h2>❌ Servicios Caídos</h2><ul>")
        for s in failed_services:
            html_alerts.append(f"<li><b>{s['name']}</b>: {s['status']}</li>")
        html_alerts.append("</ul>")

    if disk_alerts:
        html_alerts.append("<h2>⚠️ Espacio en Disco</h2><ul>")
        for d in disk_alerts:
            html_alerts.append(f"<li><b>{d['path']}</b>: {d['msg']}</li>")
        html_alerts.append("</ul>")

    style = "body{font-family:Arial;background:#f4f4f4;padding:20px} .box{background:#fff;padding:20px;border-radius:5px;border:1px solid #ddd} h2{color:#d9534f;border-bottom:1px solid #eee}"
    body = f"<html><head><style>{style}</style></head><body><div class='box'><h1>Reporte Wazuh: {h} ({ip})</h1>{''.join(html_alerts)}<br><small>Fecha: {datetime.now()}</small></div></body></html>"
    
    send_smtp_email(f"⚠️ Alerta Wazuh: {h}", body)
    log_message("--- Fin del ciclo ---")

if __name__ == "__main__":
    try:
        cfg = load_config(CONFIG_FILE_PATH)
        apply_config(cfg)
        main_logic()
    except SystemExit: pass
    except Exception as e:
        log_message(f"FATAL: {e}", "CRITICAL")
