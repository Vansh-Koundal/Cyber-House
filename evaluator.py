# evaluator.py
import json
from aiml_engine import classify_device
from statistics import mean
from functools import lru_cache

TYPE_WEIGHT = {"Smart Security Camera": 1.5, "Baby Monitor": 1.5, "NAS / Shared Storage": 1.3,
               "Smart Speaker": 1.2, "Router / Gateway": 1.2}
LAN_EXPECTED = {"Router / Gateway": {80}}

def evaluate_device_risk(open_ports, risk_db, label=None, weight=1.0):
    total, risks = 0, []
    for port in open_ports:
        key = str(port)
        if key not in risk_db:
            continue
        if isinstance(port, int) and port in LAN_EXPECTED.get(label, ()):
            continue
        info = risk_db[key]
        ded = round(info["risk_deduction"] * weight)
        total += ded
        risks.append({"port": port, "name": info["name"], "severity": info["severity"],
                      "description": info["description"], "action": info["action"], "deduction": ded})
    return total, risks


def calculate_health_index(devices_scan_data, risk_db_path="risk_db.json"):
    risk_db = load_risk_db(risk_db_path)
    processed, health = [], []
    for device in devices_scan_data:
        cls = device.get("classification") or classify_device(device)
        sure = not cls.get("uncertain")
        deduction, risks = evaluate_device_risk(
            device.get("open_ports", []), risk_db,
            label=cls["label"] if sure else None,
            weight=TYPE_WEIGHT.get(cls["label"], 1.0) if sure else 1.0)
        dev = device.copy()
        dev.update(classification=cls, risks=risks, penalty=deduction,
                   status="SECURE" if not risks else ("HIGH RISK" if deduction >= 25 else "WARNING"))
        processed.append(dev)
        health.append(max(0, 100 - deduction))
    score = round(0.6 * mean(health) + 0.4 * min(health)) if health else 100
    return {"score": score,
            "status": "EXCELLENT" if score >= 80 else ("NEEDS ATTENTION" if score >= 50 else "CRITICAL"),
            "devices": processed}

@lru_cache(maxsize=None)
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
