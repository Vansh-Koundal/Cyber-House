# evaluator.py
import json
import os
from functools import lru_cache
from statistics import mean

from aiml_engine import classify_device

TYPE_WEIGHT = {"Smart Security Camera": 1.5, "Baby Monitor": 1.5, "NAS / Shared Storage": 1.3,
               "Smart Speaker": 1.2, "Router / Gateway": 1.2}
LAN_EXPECTED = {"Router / Gateway": {80}}  # admin page on the home LAN is normal
DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "risk_db.json")


@lru_cache(maxsize=None)
def load_risk_db(db_path=DEFAULT_DB):
    with open(db_path, "r") as f:
        return json.load(f)


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
                      "description": info["description"], "action": info["action"],
                      "deduction": ded})
    return total, risks


def calculate_health_index(devices_scan_data, risk_db_path=DEFAULT_DB):
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