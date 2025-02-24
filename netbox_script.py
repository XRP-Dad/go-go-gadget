# Go Go Gadget Netbox Integration Script

import os
import requests
import time
from pyzabbix import ZabbixAPI

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
        print(f"Error: Environment variable {var} is not set")
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
    response = requests.post(f"{GOGOGADGET_SERVER}/start-check", json=payload, headers=headers)
    if response.status_code == 200:
        return response.json()["task_id"]
    print(f"Failed to start Go Go Gadget check: {response.status_code} - {response.text}")
    return None

def get_task_results(task_id):
    """Poll Go Go Gadget server for task results until available"""
    headers = {"Authorization": f"Bearer {GOGOGADGET_API_TOKEN}"}
    while True:
        response = requests.get(f"{GOGOGADGET_SERVER}/get-results?task_id={task_id}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data:  # Results available
                return data
        elif response.status_code != 404:
            print(f"Error fetching Go Go Gadget results: {response.status_code} - {response.text}")
            return None
        time.sleep(10)  # Wait 10 seconds before retrying

# Example usage for testing
if __name__ == "__main__":
    target_host = "8.8.8.8"
    task_id = start_check(target_host)
    if task_id:
        print(f"Go Go Gadget started task: {task_id}")
        results = get_task_results(task_id)
        if results:
            print(f"Go Go Gadget results for {target_host}: {results}")
        else:
            print("Failed to retrieve Go Go Gadget results")
