# Go Go Gadget Netbox Integration Script

import os
import requests
import time
import logging
from pyzabbix import ZabbixAPI

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.FileHandler("netbox_script.log"), logging.StreamHandler()])
logger = logging.getLogger(__name__)

# Load environment variables for configuration
GOGOGADGET_API_TOKEN = os.getenv("GOGOGADGET_API_TOKEN")
ZABBIX_USER = os.getenv("ZABBIX_USER")
ZABBIX_PASS = os.getenv("ZABBIX_PASS")
ZABBIX_URL = os.getenv("ZABBIX_URL", "http://zabbix-server/zabbix")
GOGOGADGET_SERVER = os.getenv("GOGOGADGET_SERVER", "http://192.168.1.10:8080")

# Validate required environment variables to ensure proper configuration
required_vars = ["GOGOGADGET_API_TOKEN", "ZABBIX_USER", "ZABBIX_PASS"]
for var in required_vars:
    if not os.getenv(var):
        logger.error(f"Environment variable {var} is not set")
        exit(1)

# Authenticate with Zabbix API to fetch proxy and community data
zapi = ZabbixAPI(ZABBIX_URL)
zapi.login(ZABBIX_USER, ZABBIX_PASS)

def get_zabbix_proxies():
    """Fetch active Zabbix proxies and their IP addresses"""
    proxies = zapi.proxy.get(output=["host", "status", "lastaccess"], selectInterfaces=["ip"])
    active_proxies = [p for p in proxies if p['status'] == '5']  # 5 indicates an active proxy
    return {p['host']: p['interfaces'][0]['ip'] for p in active_proxies}

def get_snmp_communities():
    """Retrieve SNMP communities from Zabbix global macros"""
    macros = zapi.usermacro.get(globalmacro=True)
    community_macros = [m for m in macros if 'SNMP_COMMUNITY' in m['macro']]
    community_macros.sort(key=lambda x: x['macro'])
    return [m['value'] for m in community_macros]

def start_check(host):
    """Initiate a reachability check via Go Go Gadget server"""
    communities = get_snmp_communities()
    payload = {
        "host": host,
        "communities": communities
    }
    headers = {"Authorization": f"Bearer {GOGOGADGET_API_TOKEN}"}
    try:
        response = requests.post(f"{GOGOGADGET_SERVER}/start-check", json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        task_id = response.json()["task_id"]
        logger.info(f"Started check for {host}, task ID: {task_id}")
        return task_id
    except requests.RequestException as e:
        logger.error(f"Failed to start check for {host}: {e}")
        return None

def get_task_results(task_id):
    """Poll Go Go Gadget server for task results until available or timeout"""
    headers = {"Authorization": f"Bearer {GOGOGADGET_API_TOKEN}"}
    start_time = time.time()
    max_wait = 300  # 5 minutes
    while time.time() - start_time < max_wait:
        try:
            response = requests.get(f"{GOGOGADGET_SERVER}/get-results?task_id={task_id}", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data:
                    logger.info(f"Retrieved results for task ID: {task_id}")
                    return data
            elif response.status_code != 404:
                logger.error(f"Error fetching results: {response.status_code} - {response.text}")
                return None
            time.sleep(10)
        except requests.RequestException as e:
            logger.error(f"Request error while fetching results: {e}")
            time.sleep(10)
    logger.error(f"Timeout waiting for results for task ID: {task_id}")
    return None

# Example usage for testing
if __name__ == "__main__":
    target_host = "8.8.8.8"
    task_id = start_check(target_host)
    if task_id:
        logger.info(f"Go Go Gadget started task: {task_id}")
        results = get_task_results(task_id)
        if results:
            logger.info(f"Go Go Gadget results for {target_host}: {results}")
        else:
            logger.error("Failed to retrieve Go Go Gadget results")
    else:
        logger.error("Failed to start Go Go Gadget check")