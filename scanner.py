# scanner.py  -  real-network scanner (ARP discovery + TCP connect scan + banner grab)
# Only scan networks you own or have permission to test.
import concurrent.futures
import platform
import re
import socket
import ssl
import subprocess
import time

import requests

HIGH_RISK_PORTS = [21, 23, 80, 445, 554, 8080]  # quick scan
DEEP_PORTS = [21, 22, 23, 80, 139, 443, 445, 554, 1883, 3389, 5555, 5900, 7547, 8080, 8443, 9100]  # deep scan

_last_error = ""
_vendor_cache = {}
_last_api_call = 0.0


def get_last_error():
    return _last_error


class ScanError(Exception):
    pass


# --------------------------------------------------------------------------- helpers
def detect_subnet():
    """Best-effort guess of the local /24 (sends no packets)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        return "192.168.1.0/24"
    finally:
        s.close()
    return ".".join(ip.split(".")[:3]) + ".0/24"


def _is_randomized(mac):
    # "locally administered" bit: phones/tablets use private Wi-Fi addresses
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def resolve_vendor(mac):
    """Offline lookup via the optional `manuf` package, then a rate-limited web lookup (OUI only)."""
    global _last_api_call
    mac = mac.upper()
    oui = mac[:8]  # first 3 bytes identify the maker; never send the full device address
    if oui in _vendor_cache:
        return _vendor_cache[oui]
    vendor = None
    if _is_randomized(mac):
        vendor = "Private Wi-Fi Address (likely a phone or tablet)"
    if vendor is None:
        try:
            from manuf import manuf
            vendor = manuf.MacParser().get_manuf_long(mac) or manuf.MacParser().get_manuf(mac)
        except Exception:
            vendor = None
    if vendor is None:
        try:
            wait = 1.1 - (time.time() - _last_api_call)  # free API allows ~1 request/second
            if wait > 0:
                time.sleep(wait)
            _last_api_call = time.time()
            r = requests.get(f"https://api.macvendors.com/{oui}", timeout=2)
            if r.status_code == 200:
                vendor = r.text.strip()
        except Exception:
            pass
    _vendor_cache[oui] = vendor or "Unknown Vendor"
    return _vendor_cache[oui]


# --------------------------------------------------------------------------- discovery
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0]
    except Exception:
        return ""


def arp_scan(ip_range, timeout=3):
    try:
        from scapy.all import ARP, Ether, conf, srp
    except Exception:
        raise ScanError("Scapy is not installed. Run: python -m pip install scapy")
    conf.verb = 0
    try:
        answered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range),
                       timeout=timeout, retry=1, verbose=False)[0]
    except Exception as e:
        raise ScanError(f"ARP scan failed ({e}). On Windows, install Npcap and run PyCharm as Administrator.")
    seen = {}
    for _, rcv in answered:
        seen[rcv.psrc] = rcv.hwsrc
    devices = [{"ip": ip, "mac": mac, "vendor": resolve_vendor(mac), "hostname": "", "open_ports": [], "banner": ""}
               for ip, mac in sorted(seen.items(), key=lambda kv: tuple(int(x) for x in kv[0].split(".")))]
    # device names (e.g. "iPhone-de-Ali", "DESKTOP-4F2K") are a strong clue; don't wait on slow lookups
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=16)
    futs = {ex.submit(resolve_hostname, d["ip"]): d for d in devices}
    done, _ = concurrent.futures.wait(futs, timeout=4)
    for f in done:
        futs[f]["hostname"] = f.result()
    ex.shutdown(wait=False, cancel_futures=True)
    return devices


# --------------------------------------------------------------------------- port scan + banners
def scan_single_port_socket(ip, port, timeout=0.8):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return port if s.connect_ex((ip, port)) == 0 else None
    except Exception:
        return None


def grab_banner(ip, port, timeout=1.5):
    """Read-only look at how a service introduces itself (Server header, page title, greeting)."""
    if port not in (21, 22, 23, 80, 554, 8080):
        return ""
    probes = {80: b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
              8080: b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
              554: b"OPTIONS rtsp://" + ip.encode() + b"/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in probes:
                s.sendall(probes[port])
            data = s.recv(1024).decode("latin-1", errors="ignore")
    except Exception:
        return ""
    parts = []
    m = re.search(r"^server:\s*(.+)$", data, re.I | re.M)
    if m:
        parts.append(m.group(1).strip())
    m = re.search(r"<title>(.*?)</title>", data, re.I | re.S)
    if m:
        parts.append(m.group(1).strip())
    if not parts and port in (21, 22, 23):
        parts.append(re.sub(r"[^\x20-\x7e]", " ", data).strip())
    return " ".join(parts)[:120]


def scan_ports_for_devices(devices, target_ports=HIGH_RISK_PORTS, workers=64):
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(scan_single_port_socket, d["ip"], p): d for d in devices for p in target_ports}
        for f in concurrent.futures.as_completed(futs):
            if f.result() is not None:
                futs[f]["open_ports"].append(f.result())
    for d in devices:
        d["open_ports"].sort()
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        jobs = {ex.submit(grab_banner, d["ip"], p): d for d in devices for p in d["open_ports"]}
        for f in concurrent.futures.as_completed(jobs):
            if f.result():
                jobs[f]["banner"] = (jobs[f]["banner"] + " " + f.result()).strip()[:160]
    return devices


# --------------------------------------------------------------------------- deep-scan checks
def scan_upnp(timeout=2.5):
    """UPnP discovery (SSDP). Returns {ip: server string} for devices that answer."""
    msg = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           b"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: upnp:rootdevice\r\n\r\n")
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(0.5)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                continue
            m = re.search(r"^server:\s*(.+)$", data.decode("latin-1", errors="ignore"), re.I | re.M)
            found[addr[0]] = m.group(1).strip() if m else "UPnP device"
    except Exception:
        pass
    finally:
        s.close()
    return found


def check_cert(ip, port):
    """Returns 'cert_expired', 'cert_selfsigned' (untrusted), or None if fine / unreachable."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    try:
        with socket.create_connection((ip, port), timeout=2) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip):
                return None
    except ssl.SSLCertVerificationError as e:
        return "cert_expired" if getattr(e, "verify_code", 0) == 10 else "cert_selfsigned"
    except Exception:
        return None


def get_wifi_security():
    """Windows (English) only: security type of the Wi-Fi this PC is connected to, else None."""
    if platform.system() != "Windows":
        return None
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return None
    m = re.search(r"^\s*Authentication\s*:\s*(.+)$", out, re.M)
    return m.group(1).strip() if m else None


def _wifi_finding(auth):
    if not auth:
        return None
    a = auth.lower()
    if a == "open":
        return "wifi_open"
    if a in ("wep", "shared") or a.startswith("wpa-"):
        return "wifi_weak"
    return None


def _find_gateway(devices):
    try:
        from scapy.all import conf
        gw = conf.route.route("0.0.0.0")[2]
        hit = next((d for d in devices if d["ip"] == gw), None)
        if hit:
            return hit
    except Exception:
        pass
    return next((d for d in devices if d["ip"].endswith(".1")), devices[0])


def add_deep_findings(devices):
    # UPnP
    upnp = scan_upnp()
    for d in devices:
        if d["ip"] in upnp:
            d["open_ports"].append("upnp")
            d["banner"] = (d["banner"] + " " + upnp[d["ip"]]).strip()[:160]
    # Certificates on HTTPS ports
    jobs = [(d, p) for d in devices for p in (443, 8443) if p in d["open_ports"]]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda j: check_cert(j[0]["ip"], j[1]), jobs))
    for (d, _), res in zip(jobs, results):
        if res and res not in d["open_ports"]:
            if res == "cert_expired" and "cert_selfsigned" in d["open_ports"]:
                d["open_ports"].remove("cert_selfsigned")
            if not (res == "cert_selfsigned" and "cert_expired" in d["open_ports"]):
                d["open_ports"].append(res)
    # Wi-Fi security belongs to the router
    finding = _wifi_finding(get_wifi_security())
    if finding:
        _find_gateway(devices)["open_ports"].append(finding)
    return devices


def run_full_network_audit(ip_range=None, target_ports=None, deep=False):
    """Returns a list of devices, or [] with the reason in get_last_error()."""
    global _last_error
    _last_error = ""
    ports = target_ports or (DEEP_PORTS if deep else HIGH_RISK_PORTS)
    try:
        devices = arp_scan(ip_range or detect_subnet())
    except ScanError as e:
        _last_error = str(e)
        return []
    if not devices:
        _last_error = "No devices answered. Check you are on the right Wi-Fi and the range matches your network."
        return []
    devices = scan_ports_for_devices(devices, ports)
    if deep:
        add_deep_findings(devices)
    return devices


if __name__ == "__main__":
    import json
    import sys
    res = run_full_network_audit(sys.argv[1] if len(sys.argv) > 1 else None)
    print(get_last_error() or json.dumps(res, indent=2))