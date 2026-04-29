import json
import requests
import os
from datetime import datetime


API_KEY = os.getenv("THEHIVE_API_KEY", "CHANGE_ME")
THEHIVE_URL = "http://THE_HIVE_IP_ADDRESS:9000/api/v1/alert"

file_name = input("Enter the JSON file name: ").strip()

# File validation
if not os.path.isfile(file_name):
    print("File not found!")
    exit()

if not file_name.endswith(".json"):
    print("Unsupported file format. Only JSON files are allowed.")
    exit()

# Load alerts
with open(file_name, "r", encoding="utf-8") as file:
    file_content = file.read()

alerts = []

for line in file_content.strip().split("\n"):
    try:
        alerts.append(json.loads(line))
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON line: {line}")
        print(f"Exception: {e}")

print(f"Total alerts found: {len(alerts)}")

confirm = input("Do you want to import alerts to TheHive? (y/n): ").lower()

if confirm != "y":
    print("Operation cancelled.")
    exit()

success = 0
failed = 0

for index, alert in enumerate(alerts):

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = rule.get("mitre", {})
    timestamp = alert.get("timestamp", "")
    full_log = alert.get("full_log", "")

    try:
        dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f+0000")
        date_ms = int(dt.timestamp() * 1000)
    except Exception:
        date_ms = int(datetime.utcnow().timestamp() * 1000)

    observables = []

    if agent.get("ip"):
        observables.append({
            "dataType": "ip",
            "data": agent["ip"],
            "message": "Agent IP"
        })

    src_ip = alert.get("data", {}).get("srcip")
    if src_ip:
        observables.append({
            "dataType": "ip",
            "data": src_ip,
            "message": "Source IP"
        })

    tags = rule.get("groups", [])
    mitre_ids = mitre.get("id", [])
    mitre_tactics = mitre.get("tactic", [])

    tags += [f"MITRE:{m}" for m in mitre_ids]
    tags += [f"Tactic:{t}" for t in mitre_tactics]

    wazuh_level = rule.get("level", 0)

    if wazuh_level <= 3:
        severity = 1
    elif wazuh_level <= 7:
        severity = 2
    elif wazuh_level <= 11:
        severity = 3
    else:
        severity = 4

    payload = {
        "type": "wazuh-alert",
        "source": f"wazuh-agent-{agent.get('name', 'unknown')}",
        "sourceRef": alert.get("id", ""),
        "title": rule.get("description", "Wazuh Alert"),
        "description": f"""
Rule: {rule.get('id')} - {rule.get('description')}
Agent: {agent.get('name')} ({agent.get('ip', 'N/A')})

Full Log:
{full_log}

MITRE ATT&CK: {', '.join(mitre_ids) if mitre_ids else 'N/A'}
Tactics: {', '.join(mitre_tactics) if mitre_tactics else 'N/A'}
""",
        "severity": severity,
        "date": date_ms,
        "tags": list(set(tags)),
        "tlp": 2,
        "pap": 2,
        "status": "New",
        "observables": observables,
        "customFields": {
            "wazuh-rule-id": {"string": str(rule.get("id", ""))},
            "wazuh-agent-name": {"string": agent.get("name", "")},
            "wazuh-agent-id": {"string": agent.get("id", "")},
            "wazuh-rule-level": {"integer": wazuh_level}
        }
    }

    try:
        response = requests.post(
            THEHIVE_URL,
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json"
            },
            json=payload
        )

        if response.status_code == 201:
            print(f"Alert {index} imported successfully")
            success += 1
        else:
            print(f"Failed: {response.status_code} - {response.text}")
            failed += 1

    except Exception as e:
        print(f"Error: {e}")
        failed += 1

print("SUMMARY")
print(f"Success: {success}")
print(f"Failed: {failed}")
