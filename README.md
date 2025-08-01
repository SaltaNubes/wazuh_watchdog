Ejecutar desde CRONTAB


#Wazuh Watchdog

*/15 * * * * /opt/wazuh_watchdog/wazuh_watchdog.py >> /opt/wazuh_watchdog/crontab.log 2>&1
