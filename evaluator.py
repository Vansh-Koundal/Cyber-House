# evaluator.py
import json
from aiml_engine import classify_device

def load_risk_db(db_path="risk_db.json"):
    with open(db_path, "r") as f:
        return json.load(f)


def evaluate_device_risk(open_ports, risk_db):
    total_deduction = 0
    identified_risks = []

    for port in open_ports:
        port_str = str(port)
        if port_str in risk_db:
            info = risk_db[port_str]
            total_deduction += info["risk_deduction"]
            identified_risks.append({
                "port": port,
                "name": info["name"],
                "severity": info["severity"],
                "description": info["description"],
                "action": info["action"]
            })

    return total_deduction, identified_risks


def calculate_health_index(devices_scan_data, risk_db_path="risk_db.json"):
    risk_db = load_risk_db(risk_db_path)
    total_deductions = 0
    processed_devices = []

    for device in devices_scan_data:
        open_ports = device.get("open_ports", [])
        deduction, risks = evaluate_device_risk(open_ports, risk_db)
        total_deductions += deduction

        device_copy = device.copy()
        device_copy["classification"] = device.get("classification") or classify_device(device)
        device_copy["risks"] = risks
        device_copy["status"] = "SECURE" if not risks else ("HIGH RISK" if deduction >= 25 else "WARNING")
        processed_devices.append(device_copy)

    # Health Index math: 100 minus cumulative risk deductions (floored at 0)
    health_score = max(0, 100 - total_deductions)

    return {
        "score": health_score,
        "status": "EXCELLENT" if health_score >= 80 else ("NEEDS ATTENTION" if health_score >= 50 else "CRITICAL"),
        "devices": processed_devices
    }