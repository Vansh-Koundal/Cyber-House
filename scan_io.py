# scan_io.py - the scan-file format shared by agent.py (writes it) and app.py (reads it)
"""
The website cannot see inside a home Wi-Fi, so a small scanner (agent.py) runs on a computer at home and
saves a JSON file. The website reads that file with parse_scan(). Because the file comes from the user's
browser, every field is validated and size-limited before the app uses it.
"""
import ipaddress
import json
import re
import time

FORMAT_VERSION = 1
MAX_BYTES = 1_000_000
MAX_DEVICES = 128
MAX_PORTS = 40
ALLOWED_FLAGS = {"upnp", "cert_expired", "cert_selfsigned", "wifi_open", "wifi_weak"}
_MAC = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


class ScanFileError(ValueError):
    """The uploaded file is not a usable CyberHouse scan. The message is safe to show to the user."""


def save_scan(devices, path, deep=False):
    payload = {"format": "cyberhouse-scan", "version": FORMAT_VERSION,
               "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"), "deep": bool(deep), "devices": devices}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def _clean_ports(ports):
    out = []
    for p in ports if isinstance(ports, list) else []:
        ok = (isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535) or (
            isinstance(p, str) and p in ALLOWED_FLAGS)
        if ok and p not in out:
            out.append(p)
    return out[:MAX_PORTS]


def _clean_device(d):
    if not isinstance(d, dict):
        return None
    try:
        ip = str(ipaddress.IPv4Address(str(d.get("ip", "")).strip()))
    except ValueError:
        return None
    mac = str(d.get("mac", "")).strip()
    return {"ip": ip, "mac": mac.upper() if _MAC.match(mac) else "",
            "vendor": str(d.get("vendor", ""))[:80] or "Unknown Vendor",
            "hostname": str(d.get("hostname", ""))[:60], "banner": str(d.get("banner", ""))[:160],
            "open_ports": _clean_ports(d.get("open_ports"))}


def parse_scan(raw):
    """bytes / str -> list of cleaned device dicts. Raises ScanFileError with a friendly message."""
    not_ours = "That doesn't look like a CyberHouse scan file. Upload the cyberhouse_scan.json the scanner saved."
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) > MAX_BYTES:
            raise ScanFileError("That file is too large to be a CyberHouse scan.")
        try:
            raw = bytes(raw).decode("utf-8-sig")
        except UnicodeDecodeError:
            raise ScanFileError(not_ours)
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        raise ScanFileError(not_ours)
    if isinstance(data, dict):
        data = data.get("devices")
    if not isinstance(data, list):
        raise ScanFileError(not_ours)
    devices = [dev for dev in (_clean_device(d) for d in data[:MAX_DEVICES]) if dev]
    if not devices:
        raise ScanFileError("The scan file has no devices in it. Run the scanner again on your home Wi-Fi.")
    return devices
