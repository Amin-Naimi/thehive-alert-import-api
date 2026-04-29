# Wazuh to TheHive Alert Importer

## Description
This project is a Python script that automatically imports Wazuh security alerts into TheHive using its REST API.

It parses JSON alerts, extracts relevant security fields, enriches them with MITRE ATT&CK data, and sends structured incidents to TheHive.

---

## Features
- Reads Wazuh JSON alerts
- Extracts rule, agent, and MITRE data
- Converts timestamps to Unix milliseconds
- Maps Wazuh severity to TheHive severity
- Sends alerts via TheHive API
- Adds observables (IP addresses)
- Adds tags and custom fields

---

## Requirements
```bash
pip install requests
