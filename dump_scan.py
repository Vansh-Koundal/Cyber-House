# dump_scan.py - scans your network and writes real_devices.csv for you to label
import csv
from scanner import run_full_network_audit, get_last_error, detect_subnet

devices = run_full_network_audit(detect_subnet(), deep=True)
if not devices:
    print("Scan failed:", get_last_error())
else:
    with open("real_devices.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "vendor", "hostname", "ports", "true_label"])
        for d in devices:
            ports = ";".join(str(p) for p in d["open_ports"] if isinstance(p, int))
            w.writerow([d["ip"], d["vendor"], d["hostname"], ports, ""])
    print(f"Wrote {len(devices)} devices to real_devices.csv")