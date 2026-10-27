import sys
import os
import json
import requests
from requests.exceptions import ConnectionError
from socket import socker, AF_UNIX, SOC_DGRAM
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MISP_BASE_URL = "https://192.168.182.132:8443"
MISP_API_KEY = "Wv5JXLz3642SzdRx0GAofp0vJtyKqtxOLlPwcFmh"

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = "{0}/queue/sockets/queue".format(pwd)

def send_event(msg, agent=None):
    if not agent or agent["id"] == "000":
        string = "1:misp:{0}".format(json.dumps(msg))
    else:
        string = "1:[{0}] ({1}) {2}->misp:{3}".format(
            agent["id"], agent["name"],
            agent["ip"] if "ip" in agent else "any",
            json.dumps(msg),
        )
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

def query_misp(ioc_value):
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    body = {"returnFormat": "json", "value": ioc_value}
    url = f"{MISP_BASE_URL}/attributes/restSearch"
    try:
        response = requests.post(url, headers=headers, json=body, verify=False, timeout=10)
        return response.json()
    except ConnectionError:
        return None

def extract_ip(alert):
    data = alert.get("data", {})
    for key in ("srcip", "dstip"):
        if key in data:
            return data[key]
    return None

def main(args):
    alert_file_path = args[1]
    with open(alert_file_path) as f:
        alert = json.load(f)
    ip_to_check = extract_ip(alert)
    if not ip_to_check:
        sys.exit(0)
    result = query_misp(ip_to_check)
    if not result:
        sys.exit(0)
    attributes = result.get("response", {}).get("Attribute", [])
    if attributes:
        msg = {
            "integration": "misp",
            "misp": {
                "ioc_value": ip_to_check,
                "matches": len(attributes),
                "details": attributes[0] if attributes else {},
            },
        }
        agent = alert.get("agent", None)
        send_event(msg, agent)

if __name__ == "__main__":
    main(sys.argv)