#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import shutil
# import boto3 # YA NO SE USA BOTO3 PARA EMAIL
# from botocore.exceptions import ClientError, NoCredentialsError # YA NO SE NECESITAN
import os
import datetime
import sys
import yaml
import re
from dotenv import load_dotenv

# NUEVAS IMPORTACIONES PARA SMTP
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header # Para codificar correctamente el asunto
from email.utils import formataddr # Para formatear el remitente con nombre

load_dotenv()

# --- Definiciones Globales de Configuración ---
CONFIG = {}
# AWS_REGION ya no es relevante para el envío de email SMTP genérico (a menos que el host SMTP lo incluya)
SENDER_DISPLAY_NAME = "Monitor Wazuh" # Nombre a mostrar en el remitente (opcional)
SENDER_EMAIL = "" # Dirección 'From' del correo
RECIPIENT_EMAILS = []
WAZUH_SERVICES = []
DISK_MONITOR_TARGETS = []
LOG_LEVEL = "INFO"

# NUEVAS GLOBALES PARA SMTP
SMTP_HOST = ""
SMTP_PORT = 0
SMTP_USE_TLS = False
SMTP_USE_SSL = False # Añadido para manejar SSL directo
SMTP_USERNAME = ""
SMTP_PASSWORD = "" # Se cargará desde .env

CONFIG_FILE_PATH = "config.yml"

# --- Carga y Aplicación de Configuración ---
def load_config(file_path):
    # ... (sin cambios) ...
    print(f"Intentando cargar configuración de la aplicación desde: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        if not config_data: print(f"[ERROR CRÍTICO] El archivo '{file_path}' está vacío."); sys.exit(1)
        print("Archivo de configuración YAML cargado."); return config_data
    except FileNotFoundError: print(f"[ERROR CRÍTICO] Archivo '{file_path}' no encontrado."); sys.exit(1)
    except yaml.YAMLError as e: print(f"[ERROR CRÍTICO] Error parseando YAML '{file_path}': {e}"); sys.exit(1)
    except Exception as e: print(f"[ERROR CRÍTICO] Error cargando '{file_path}': {e}"); sys.exit(1)


def is_valid_email(email):
    # ... (sin cambios) ...
    if not isinstance(email, str): return False
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

def apply_config(loaded_config):
    global CONFIG, SENDER_EMAIL, RECIPIENT_EMAILS, WAZUH_SERVICES, DISK_MONITOR_TARGETS, LOG_LEVEL, \
           SMTP_HOST, SMTP_PORT, SMTP_USE_TLS, SMTP_USE_SSL, SMTP_USERNAME, SMTP_PASSWORD, SENDER_DISPLAY_NAME
    
    CONFIG = loaded_config

    # Configuración de Email (SMTP)
    email_cfg_main = CONFIG.get('email_settings', {})
    smtp_config = email_cfg_main.get('smtp')
    if not smtp_config or not isinstance(smtp_config, dict):
        print("[ERROR CRÍTICO DE CONFIGURACIÓN] La sección 'email_settings.smtp' falta o no es válida en config.yml.")
        sys.exit(1)
    
    SMTP_HOST = smtp_config.get('host')
    SMTP_PORT = smtp_config.get('port')
    SMTP_USE_TLS = smtp_config.get('use_tls', False) # Default a False si no está
    SMTP_USE_SSL = smtp_config.get('use_ssl', False) # Default a False si no está
    SMTP_USERNAME = smtp_config.get('username')
    SENDER_EMAIL = smtp_config.get('sender_email') # 'From' address
    RECIPIENT_EMAILS_CFG = smtp_config.get('recipient_emails')
    SENDER_DISPLAY_NAME = smtp_config.get('sender_display_name', "Monitor Wazuh") # Nombre opcional

    # Cargar contraseña SMTP desde .env
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

    # Validaciones críticas para SMTP
    if not all([SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SENDER_EMAIL]):
        print("[ERROR CRÍTICO DE CONFIGURACIÓN SMTP] Faltan 'host', 'port', 'username', 'sender_email' en 'email_settings.smtp' o SMTP_PASSWORD en .env.")
        sys.exit(1)
    try:
        SMTP_PORT = int(SMTP_PORT)
    except ValueError:
        print(f"[ERROR CRÍTICO DE CONFIGURACIÓN SMTP] El puerto SMTP '{SMTP_PORT}' debe ser un número.")
        sys.exit(1)

    if SMTP_USE_TLS and SMTP_USE_SSL:
        print("[ERROR CRÍTICO DE CONFIGURACIÓN SMTP] No se pueden activar 'use_tls' y 'use_ssl' al mismo tiempo.")
        sys.exit(1)
    if SMTP_PORT == 465 and not SMTP_USE_SSL:
         print("[ADVERTENCIA DE CONFIGURACIÓN SMTP] El puerto 465 usualmente implica SSL directo ('use_ssl: true').")
    if SMTP_PORT != 465 and SMTP_USE_SSL:
         print("[ADVERTENCIA DE CONFIGURACIÓN SMTP] 'use_ssl: true' usualmente se usa con el puerto 465.")


    # Validar SENDER_EMAIL
    if not is_valid_email(SENDER_EMAIL):
        print(f"[ERROR CRÍTICO] 'sender_email' ({SENDER_EMAIL}) en config.yml no es válido.")
        sys.exit(1)

    # Procesar y validar RECIPIENT_EMAILS (como antes)
    if not RECIPIENT_EMAILS_CFG: print("[ERROR CRÍTICO] 'recipient_emails' falta en config.yml."); sys.exit(1)
    if isinstance(RECIPIENT_EMAILS_CFG, str): RECIPIENT_EMAILS_TMP = [RECIPIENT_EMAILS_CFG.strip()]
    elif isinstance(RECIPIENT_EMAILS_CFG, list): RECIPIENT_EMAILS_TMP = [str(r).strip() for r in RECIPIENT_EMAILS_CFG if str(r).strip()]
    else: print("[ERROR CRÍTICO] 'recipient_emails' debe ser cadena o lista."); sys.exit(1)
    if not RECIPIENT_EMAILS_TMP: print("[ERROR CRÍTICO] Lista 'recipient_emails' vacía."); sys.exit(1)
    valid_recipients = []
    for email_addr in RECIPIENT_EMAILS_TMP:
        if not is_valid_email(email_addr): print(f"[ERROR CRÍTICO] Email destinatario '{email_addr}' inválido."); sys.exit(1)
        valid_recipients.append(email_addr)
    RECIPIENT_EMAILS = valid_recipients
    if not RECIPIENT_EMAILS: print("[ERROR CRÍTICO] No hay destinatarios válidos."); sys.exit(1)
    
    # Wazuh, Disk, Global settings (como antes)
    # ... (copiar las validaciones de estas secciones del script anterior) ...
    wazuh_config = CONFIG.get('wazuh_monitoring')
    if not wazuh_config or not isinstance(wazuh_config, dict): print("[ERROR CRÍTICO] Sección 'wazuh_monitoring' falta o inválida."); sys.exit(1)
    WAZUH_SERVICES = wazuh_config.get('services')
    if not WAZUH_SERVICES or not isinstance(WAZUH_SERVICES, list) or not WAZUH_SERVICES: print("[ERROR CRÍTICO] 'services' (lista) en 'wazuh_monitoring' falta o vacía."); sys.exit(1)
    disk_config_main = CONFIG.get('disk_monitoring')
    if not disk_config_main or not isinstance(disk_config_main, dict): print("[ERROR CRÍTICO] Sección 'disk_monitoring' falta o inválida."); sys.exit(1)
    monitored_paths_config = disk_config_main.get('monitored_paths')
    if not monitored_paths_config or not isinstance(monitored_paths_config, list) or not monitored_paths_config: print("[ERROR CRÍTICO] 'monitored_paths' (lista) en 'disk_monitoring' falta o vacía."); sys.exit(1)
    temp_disk_targets = []
    for i, item in enumerate(monitored_paths_config):
        if not isinstance(item, dict): print(f"[ERROR CRÍTICO] Elemento {i+1} en 'monitored_paths' no es objeto."); sys.exit(1)
        path_to_check = item.get('path')
        threshold_val = item.get('threshold_percentage')
        if not path_to_check or not isinstance(path_to_check, str): print(f"[ERROR CRÍTICO] 'path' inválido en elemento {i+1} de 'monitored_paths'."); sys.exit(1)
        if threshold_val is None: print(f"[ERROR CRÍTICO] 'threshold_percentage' falta en elemento {i+1} ('{path_to_check}')."); sys.exit(1)
        try:
            threshold_percent = int(threshold_val)
            if not (0 <= threshold_percent <= 100): raise ValueError()
            temp_disk_targets.append({'path': path_to_check, 'threshold': threshold_percent})
        except ValueError: print(f"[ERROR CRÍTICO] 'threshold_percentage' ('{threshold_val}') para '{path_to_check}' debe ser entero 0-100."); sys.exit(1)
    DISK_MONITOR_TARGETS = temp_disk_targets
    if not DISK_MONITOR_TARGETS: print("[ERROR CRÍTICO] No se configuraron rutas de disco válidas."); sys.exit(1)
    global_cfg = CONFIG.get('global_settings')
    if global_cfg and isinstance(global_cfg, dict): LOG_LEVEL = global_cfg.get('log_level', "INFO").upper()
    else: print("[ADVERTENCIA] Sección 'global_settings' no encontrada/inválida. Usando LOG_LEVEL='INFO'.")

    print("Validación de configuración de aplicación completada.")


# --- Funciones de Verificación (check_wazuh_services, check_disk_space sin cambios) ---
def check_wazuh_services():
    # ... (código como antes) ...
    failed_services = []
    active_services = []
    print(f"\nVerificando servicios de Wazuh (según config.yml): {', '.join(WAZUH_SERVICES)}")
    for service in WAZUH_SERVICES:
        try:
            result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True, check=False)
            status = result.stdout.strip()
            if status == "active":
                if LOG_LEVEL == "DEBUG": print(f"  [DEBUG] Servicio '{service}' está activo.")
                active_services.append(service)
            else:
                error_details = result.stderr.strip() if result.stderr else f"El servicio reportó '{status}'."
                print(f"  [FALLA] Servicio '{service}' NO está activo (estado: {status}, rc: {result.returncode}). Detalles: {error_details}")
                failed_services.append({"name": service, "status": status, "details": error_details})
        except FileNotFoundError:
            msg = "Comando 'systemctl' no encontrado."
            print(f"  [ERROR] {msg}"); failed_services.append({"name": service, "status": "error_systemctl", "details": msg}); break
        except Exception as e:
            print(f"  [ERROR] Excepción verificando '{service}': {e}"); failed_services.append({"name": service, "status": "exception", "details": str(e)})
    if not failed_services: print("  [OK] Todos los servicios de Wazuh monitorizados están activos.")
    return failed_services, active_services

def check_disk_space(path, threshold_percent):
    # ... (código como antes) ...
    try:
        usage = shutil.disk_usage(path)
        free_percent = (usage.free / usage.total) * 100
        if LOG_LEVEL == "DEBUG": print(f"    [DEBUG] Ruta '{path}': Libre: {free_percent:.2f}%")
        is_below_threshold = free_percent < threshold_percent
        if is_below_threshold: print(f"  [ALERTA] Ruta '{path}': espacio libre ({free_percent:.2f}%) POR DEBAJO del umbral ({threshold_percent}%)")
        else: print(f"  [OK] Ruta '{path}': espacio libre ({free_percent:.2f}%) por encima del umbral ({threshold_percent}%)")
        return free_percent, is_below_threshold
    except FileNotFoundError: print(f"  [ERROR] Ruta '{path}' no encontrada."); return -1, True
    except Exception as e: print(f"  [ERROR] Excepción verificando disco para '{path}': {e}"); return -1, True

# --- NUEVA FUNCIÓN DE ENVÍO DE CORREO SMTP ---
def send_smtp_email(subject_str, body_html):
    """Envía un correo electrónico usando SMTP."""
    if not all([SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SENDER_EMAIL, RECIPIENT_EMAILS]):
        print("  [ERROR DE CONFIGURACIÓN SMTP] Faltan datos para enviar correo. Revisa config.yml y .env.")
        return False

    msg = MIMEMultipart('alternative')
    # Codificar el asunto correctamente para caracteres especiales
    msg['Subject'] = Header(subject_str, 'utf-8').encode()
    # Formatear el remitente para incluir un nombre visible (opcional)
    msg['From'] = formataddr((str(Header(SENDER_DISPLAY_NAME, 'utf-8')), SENDER_EMAIL))
    msg['To'] = ", ".join(RECIPIENT_EMAILS) # Cabecera 'To' como string

    # Adjuntar cuerpo HTML
    try:
        part_html = MIMEText(body_html, 'html', 'utf-8')
        msg.attach(part_html)
    except Exception as e:
        print(f"  [ERROR] No se pudo crear el cuerpo del mensaje MIME: {e}")
        return False
        
    server = None # Inicializar server a None
    try:
        if SMTP_USE_SSL: # Conexión SSL directa (usualmente puerto 465)
            print(f"  Conectando a SMTP SSL: {SMTP_HOST} en puerto {SMTP_PORT}...")
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10)
        else: # Conexión estándar (puede usar STARTTLS)
            print(f"  Conectando a SMTP: {SMTP_HOST} en puerto {SMTP_PORT}...")
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
            if SMTP_USE_TLS:
                print("  Iniciando TLS...")
                server.starttls()
        
        if LOG_LEVEL == "DEBUG":
            server.set_debuglevel(1) # Muestra la comunicación SMTP
            
        print(f"  Autenticando con usuario: {SMTP_USERNAME}...")
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        
        print(f"  Enviando correo a: {', '.join(RECIPIENT_EMAILS)}")
        # sendmail necesita una lista de destinatarios, no un string
        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAILS, msg.as_string())
        print(f"  [ÉXITO] Correo enviado vía SMTP.")
        return True

    except smtplib.SMTPAuthenticationError as e:
        print(f"  [ERROR DE AUTENTICACIÓN SMTP] {e}")
        print("  Verifica el nombre de usuario SMTP, contraseña y la configuración del servidor (puerto, TLS/SSL).")
        return False
    except smtplib.SMTPServerDisconnected as e:
        print(f"  [ERROR SMTP] El servidor se desconectó inesperadamente: {e}")
        return False
    except smtplib.SMTPConnectError as e:
        print(f"  [ERROR SMTP] No se pudo conectar al servidor SMTP ({SMTP_HOST}:{SMTP_PORT}): {e}")
        return False
    except smtplib.SMTPHeloError as e:
        print(f"  [ERROR SMTP] El servidor no respondió correctamente al saludo HELO/EHLO: {e}")
        return False
    except smtplib.SMTPRecipientsRefused as e:
        print(f"  [ERROR SMTP] Todos los destinatarios fueron rechazados: {e.recipients}") # e.recipients es un diccionario
        return False
    except smtplib.SMTPSenderRefused as e:
        print(f"  [ERROR SMTP] El servidor rechazó la dirección del remitente ({SENDER_EMAIL}): {e.smtp_error}")
        return False
    except smtplib.SMTPDataError as e:
        print(f"  [ERROR SMTP] El servidor rechazó los datos del mensaje: {e.smtp_error}")
        return False
    except smtplib.SMTPException as e: # Captura otras excepciones de smtplib
        print(f"  [ERROR SMTP] Ocurrió un error general de SMTP: {e}")
        return False
    except ConnectionRefusedError as e: # Más específico para problemas de conexión
        print(f"  [ERROR DE RED] Conexión rechazada al intentar conectar a {SMTP_HOST}:{SMTP_PORT}. ¿Está el servidor disponible y el puerto es correcto?")
        return False
    except TimeoutError as e: # Si la conexión o una operación excede el timeout
        print(f"  [ERROR DE TIMEOUT] Se agotó el tiempo de espera conectando o comunicándose con {SMTP_HOST}:{SMTP_PORT}.")
        return False
    except Exception as e:
        print(f"  [ERROR INESPERADO AL ENVIAR CORREO SMTP] Tipo: {type(e).__name__}, Error: {e}")
        return False
    finally:
        if server:
            try:
                print("  Cerrando conexión SMTP...")
                server.quit()
            except smtplib.SMTPServerDisconnected:
                print("  El servidor ya estaba desconectado al intentar cerrar.")
            except Exception as e_quit:
                print(f"  Error al cerrar la conexión SMTP: {e_quit}")


# --- Lógica Principal (main_logic) ---
# CAMBIO: Ahora llama a send_smtp_email en lugar de send_ses_email
def main_logic():
    # ... (código como antes para obtener hostname, timestamp, verificaciones) ...
    print("\n--- Iniciando Script de Verificación ---")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
    try: hostname = os.uname().nodename
    except AttributeError: import socket; hostname = socket.gethostname()

    failed_wazuh_services, active_wazuh_services = check_wazuh_services()
    disk_space_alerts_details = []; disk_space_ok_reports = []; any_disk_alert_triggered = False
    print(f"\n--- Verificando Espacio en Disco para {len(DISK_MONITOR_TARGETS)} ruta(s) ---")
    for target in DISK_MONITOR_TARGETS:
        path, threshold = target['path'], target['threshold']
        if LOG_LEVEL == "DEBUG": print(f"  Verificando: Ruta='{path}', Umbral='{threshold}%'")
        free_percent, alert_triggered = check_disk_space(path, threshold)
        if alert_triggered:
            any_disk_alert_triggered = True
            if free_percent == -1: disk_space_alerts_details.append({'path': path, 'message': "<b>Error crítico verificando espacio.</b>"})
            else: disk_space_alerts_details.append({'path': path, 'message': f"Espacio libre <b>{free_percent:.2f}%</b> < umbral <b>{threshold}%</b>."})
        elif free_percent != -1: disk_space_ok_reports.append({'path': path, 'free_percent': free_percent, 'threshold': threshold})
    if not any_disk_alert_triggered and DISK_MONITOR_TARGETS: print("  [OK] Todas las rutas de disco OK.")

    issues_found = failed_wazuh_services or any_disk_alert_triggered
    email_subject = f"Informe de Salud Servidor Wazuh: {hostname}"
    if issues_found: email_subject = f"⚠️ Alerta de Salud Servidor Wazuh: {hostname}"

    if issues_found:
        print("\n--- Se detectaron problemas. Preparando correo de alerta. ---")
        alert_messages_html = []
        if failed_wazuh_services:
            alert_messages_html.append("<h2>❌ Fallos en Servicios de Wazuh:</h2><ul>")
            for s in failed_wazuh_services: alert_messages_html.append(f"<li><b>{s['name']}</b>: {s['status']} <pre>{s['details'].replace('<', '&lt;').replace('>', '&gt;')}</pre></li>") # Escapar HTML
            alert_messages_html.append("</ul>")
        if any_disk_alert_triggered:
            alert_messages_html.append("<h2>⚠️ Alertas de Espacio en Disco:</h2><ul>")
            for a in disk_space_alerts_details: alert_messages_html.append(f"<li><b>Ruta: {a['path']}</b><br>{a['message']}</li>")
            alert_messages_html.append("</ul>")
        
        body_html_parts = [
            f"<html><head><style>"
            f"body {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; color: #333; }}"
            f".container {{ max-width: 600px; margin: 20px auto; background-color: #ffffff; border: 1px solid #dddddd; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}"
            f".header {{ background-color: {'#d9534f' if issues_found else '#5cb85c'}; color: white; padding: 20px; text-align: center; border-top-left-radius: 8px; border-top-right-radius: 8px; }}" # Color header
            f".content {{ padding: 20px; line-height: 1.6; }}"
            f"h1 {{ font-size: 24px; color: {'#d9534f' if issues_found else '#5cb85c'}; margin-top:0; }}"
            f"h2 {{ font-size: 20px; color: #c9302c; border-bottom: 1px solid #eeeeee; padding-bottom: 10px; }}"
            f"h3 {{ font-size: 18px; color: #555; }}"
            f"ul {{ list-style-type: none; padding-left: 0; }}"
            f"li {{ background-color: #f9f9f9; border: 1px solid #ddd; margin-bottom: 10px; padding: 15px; border-radius: 4px; }}"
            f"li b {{ color: #555; }}"
            f"pre {{ background-color: #eeeeee; padding: 10px; border-radius: 3px; white-space: pre-wrap; word-wrap: break-word; font-size: 0.9em; border: 1px solid #ccc;}}"
            f".ok {{ color: #5cb85c; font-weight: bold; }}"
            f".footer {{ text-align: center; padding: 15px; font-size: 0.8em; color: #aaaaaa; background-color: #f9f9f9; border-bottom-left-radius: 8px; border-bottom-right-radius: 8px; }}"
            f"</style></head><body>"
            f"<div class='container'>"
            f"<div class='header'><h1>{'Informe de Alerta' if issues_found else 'Informe de Estado'} del Servidor Wazuh</h1></div>"
            f"<div class='content'>"
            f"<p><strong>Servidor:</strong> {hostname}<br>"
            f"<strong>Fecha y Hora del Reporte:</strong> {timestamp}</p>"]
        body_html_parts.extend(alert_messages_html)
        if active_wazuh_services: body_html_parts.append("<hr><h2>✅ Servicios Activos:</h2><ul>" + "".join([f"<li><b>{s}</b>: <span class='ok'>Activo</span></li>" for s in active_wazuh_services]) + "</ul>")
        if disk_space_ok_reports: body_html_parts.append("<hr><h3>ℹ️ Rutas de Disco OK:</h3><ul>" + "".join([f"<li><b>Ruta: {r['path']}</b>: {r['free_percent']:.2f}% libre (Umbral {r['threshold']}%) - <span class='ok'>OK</span></li>" for r in disk_space_ok_reports]) + "</ul>")
        body_html_parts.append(f"</div><div class='footer'>Este es un mensaje automatizado.</div></div></body></html>")
        email_body = "".join(body_html_parts)

        send_smtp_email(email_subject, email_body) # CAMBIO: Llamada a la nueva función
    else:
        print("\n--- ✔️ No se detectaron problemas. Todo OK. ---")
        # Opcional: enviar correo de "Todo OK" usando send_smtp_email
        # subject_ok = f"✅ Informe de Salud Servidor Wazuh: {hostname} - TODO OK"
        # html_ok = f"<html>...<h1>Todo OK en {hostname}</h1>..." # Construir HTML simple
        # send_smtp_email(subject_ok, html_ok)

    print("\n--- Script de Verificación Finalizado ---")


if __name__ == "__main__":
    loaded_config_data = load_config(CONFIG_FILE_PATH)
    apply_config(loaded_config_data)
    main_logic()
