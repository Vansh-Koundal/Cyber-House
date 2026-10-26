# app.py  -  Household Cyber Health Dashboard
import html
import math
import os
import time

import streamlit as st

from scanner import run_full_network_audit, detect_subnet, get_last_error
from scan_io import ScanFileError, parse_scan
from aiml_engine import (classify_device, model_report, explain_risk, save_user_label, make_label_record,
                         get_classifier, DeviceClassifier, DEVICE_META)
from evaluator import calculate_health_index
from pdf_generator import generate_pdf_report

st.set_page_config(page_title="CyberHouse", page_icon="🛡️", layout="wide")

# -----------------------------------------------------------------------------
# 1. Design tokens + CSS
# -----------------------------------------------------------------------------
C_OK, C_WARN, C_BAD, C_ACCENT = "#2DE2A6", "#FFB547", "#FF4D6D", "#38D9FF"

st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500&family=IBM+Plex+Mono:wght@400;500&display=swap');
:root {{ --bg:#05070D; --panel:#0B1220; --line:#16233A; --text:#E6EEF9; --muted:#7C8DA8;
        --ok:{C_OK}; --warn:{C_WARN}; --bad:{C_BAD}; --accent:{C_ACCENT}; }}
.stApp {{ background:
    radial-gradient(900px 500px at 85% -10%, rgba(56,217,255,.10), transparent 60%),
    radial-gradient(700px 400px at -10% 30%, rgba(45,226,166,.06), transparent 60%),
    var(--bg);
  color:var(--text); font-family:'IBM Plex Sans',sans-serif; }}
header[data-testid="stHeader"] {{ background:transparent; }}
, [data-testid="stDeployButton"], #MainMenu {{ display:none !important; }}
.block-container {{ padding-top:2rem; max-width:1250px; }}
h1,h2,h3,h4 {{ font-family:'Chakra Petch',sans-serif !important; letter-spacing:.01em; color:var(--text); }}
section[data-testid="stSidebar"] {{ background:#070B14; border-right:1px solid var(--line); }}

.panel {{ background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:22px; height:100%; }}
.panel-title {{ font-family:'Chakra Petch'; font-weight:600; font-size:1.05rem; margin-bottom:4px; }}
.muted {{ color:var(--muted); font-size:.9rem; }}
.mono {{ font-family:'IBM Plex Mono',monospace; font-size:.82rem; color:var(--muted); }}

/* Hero */
.hero-title {{ font-family:'Chakra Petch'; font-weight:700; font-size:2.1rem; line-height:1.1; margin:0; }}
.hero-sub {{ color:var(--muted); margin:.4rem 0 1.4rem; max-width:60ch; }}

/* Score ring: animates from the previous score to the new one */
@property --n {{ syntax:'<integer>'; initial-value:0; inherits:false; }}
.ring-wrap {{ position:relative; width:230px; height:230px; margin:auto; }}
.ring-wrap svg {{ transform:rotate(-90deg); }}
.ring-track {{ stroke:#122038; }}
.ring-bar {{ stroke-dasharray:502.65; stroke-linecap:round;
  animation:ringfill 1.4s cubic-bezier(.2,.8,.2,1) both; filter:drop-shadow(0 0 8px var(--ringc)); }}
@keyframes ringfill {{ from {{ stroke-dashoffset:var(--from); }} to {{ stroke-dashoffset:var(--to); }} }}
.ring-num {{ position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; }}
.ring-num b {{ font-family:'Chakra Petch'; font-size:3.4rem; line-height:1; animation:count 1.4s ease-out both; counter-reset:n var(--n); }}
.ring-num b::after {{ content:counter(n); }}
@keyframes count {{ from {{ --n:var(--nfrom); }} to {{ --n:var(--nto); }} }}
.ring-num span {{ color:var(--muted); font-size:.8rem; margin-top:4px; }}

/* Stats */
.stat {{ border-left:2px solid var(--line); padding:2px 0 2px 14px; margin-bottom:14px; }}
.stat b {{ font-family:'Chakra Petch'; font-size:1.7rem; display:block; line-height:1.1; }}
.stat span {{ color:var(--muted); font-size:.85rem; }}

/* Badges */
.badge {{ display:inline-block; padding:2px 10px; border-radius:3px; font-family:'IBM Plex Mono'; font-size:.75rem; border:1px solid; }}
.b-ok {{ color:var(--ok); border-color:rgba(45,226,166,.4); background:rgba(45,226,166,.08); }}
.b-warn {{ color:var(--warn); border-color:rgba(255,181,71,.4); background:rgba(255,181,71,.08); }}
.b-bad {{ color:var(--bad); border-color:rgba(255,77,109,.45); background:rgba(255,77,109,.08); }}

/* Radar */
.sweep {{ transform-origin:200px 200px; animation:spin 6s linear infinite; }}
@keyframes spin {{ to {{ transform:rotate(360deg); }} }}
.pulse {{ animation:pulse 2.2s ease-in-out infinite; transform-box:fill-box; transform-origin:center; }}
@keyframes pulse {{ 50% {{ transform:scale(1.35); opacity:.5; }} }}

/* Device + fix rows */
.dev-head {{ display:flex; align-items:center; gap:12px; }}
.dev-ico {{ font-size:1.6rem; width:44px; height:44px; display:flex; align-items:center; justify-content:center;
  background:#0E1930; border:1px solid var(--line); border-radius:6px; }}
.risk {{ border-left:3px solid var(--bad); background:rgba(255,255,255,.02); padding:10px 14px; margin:10px 0 4px; border-radius:0 4px 4px 0; }}
.risk.MEDIUM {{ border-color:var(--warn); }} .risk.LOW {{ border-color:var(--accent); }}
.risk h5 {{ margin:0 0 4px; font-family:'Chakra Petch'; font-size:1rem; }}
.risk p {{ margin:2px 0; color:#B7C4D9; font-size:.92rem; }}

/* Streamlit widget overrides */
.stTabs [data-baseweb="tab-list"] {{ gap:4px; border-bottom:1px solid var(--line); }}
.stTabs [data-baseweb="tab"] {{ font-family:'Chakra Petch'; font-weight:600; color:var(--muted); padding:10px 18px; }}
.stTabs [aria-selected="true"] {{ color:var(--accent) !important; }}
.stTabs [data-baseweb="tab-highlight"] {{ background:var(--accent); }}
div[data-testid="stExpander"] {{ background:var(--panel); border:1px solid var(--line); border-radius:6px; }}
.stButton>button, .stDownloadButton>button {{ border-radius:4px; border:1px solid var(--line); background:#0E1930;
  color:var(--text); font-family:'Chakra Petch'; font-weight:600; transition:border-color .15s, box-shadow .15s; }}
.stButton>button:hover, .stDownloadButton>button:hover {{ border-color:var(--accent); color:var(--accent); box-shadow:0 0 0 1px var(--accent); }}
.stButton>button:focus-visible {{ outline:2px solid var(--accent); outline-offset:2px; }}
button[kind="primary"] {{ background:var(--accent) !important; color:#031018 !important; border-color:var(--accent) !important; }}
@media (prefers-reduced-motion: reduce) {{ .ring-bar,.ring-num b,.sweep,.pulse {{ animation:none !important; }} }}
.stApp::before {{ content:""; position:fixed; inset:0; pointer-events:none;
  background-image:linear-gradient(rgba(56,217,255,.04) 1px, transparent 1px), linear-gradient(90deg, rgba(56,217,255,.04) 1px, transparent 1px);
  background-size:42px 42px; mask-image:radial-gradient(ellipse at 50% 20%, #000 30%, transparent 75%); }}
.hero-grad {{ background:linear-gradient(90deg,#E6EEF9,#38D9FF 60%,#2DE2A6); -webkit-background-clip:text; background-clip:text;
  color:transparent; font-family:'Chakra Petch'; font-weight:700; font-size:3rem; line-height:1.05; margin:0 0 .6rem; }}
.feat {{ display:flex; gap:12px; align-items:flex-start; padding:12px 0; border-top:1px solid var(--line); }}
.feat i {{ font-style:normal; font-size:1.3rem; min-width:38px; height:38px; display:flex; align-items:center; justify-content:center;
  background:#0E1930; border:1px solid var(--line); border-radius:6px; }}
.feat b {{ font-family:'Chakra Petch'; display:block; }}
.feat span {{ color:var(--muted); font-size:.9rem; }}
.panel {{ transition:border-color .2s, box-shadow .2s; }}
.panel:hover {{ border-color:rgba(56,217,255,.45); box-shadow:0 0 24px rgba(56,217,255,.08); }}
.consent {{ border:1px solid rgba(255,181,71,.45); background:rgba(255,181,71,.07); border-radius:6px;
  padding:10px 12px; font-size:.82rem; color:#EAD7AE; margin:8px 0 2px; }}
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# 2. Simulation scenarios
# -----------------------------------------------------------------------------
MOCK_SCENARIOS = {
    "Insecure smart home": [
        {"ip": "192.168.1.1", "mac": "00:14:D1:A2:88:01", "vendor": "TP-Link Technologies", "hostname": "tplinkwifi", "open_ports": [80, 8080]},
        {"ip": "192.168.1.105", "mac": "24:0A:C4:88:12:4A", "vendor": "Espressif Inc", "hostname": "ipcam-livingroom", "open_ports": [23, 554]},
        {"ip": "192.168.1.112", "mac": "64:16:66:33:B1:02", "vendor": "Samsung Electronics", "hostname": "Samsung-TV", "open_ports": [21, 8080]},
        {"ip": "192.168.1.150", "mac": "A4:C1:38:11:22:33", "vendor": "Synology Incorporated", "hostname": "DiskStation", "open_ports": [445, 21]},
    ],
    "Smart nursery": [
        {"ip": "192.168.1.1", "mac": "00:14:D1:A2:88:01", "vendor": "Netgear", "hostname": "router", "open_ports": [80]},
        {"ip": "192.168.1.108", "mac": "AC:67:B2:44:55:66", "vendor": "Nanit", "hostname": "nanit-cam", "open_ports": [554, 23]},
        {"ip": "192.168.1.115", "mac": "50:02:91:77:88:99", "vendor": "Amazon Technologies Inc.", "hostname": "Echo-Dot", "open_ports": [8080]},
    ],
    "Typical family home": [
        {"ip": "192.168.1.1", "mac": "00:14:D1:A2:88:01", "vendor": "NETGEAR", "hostname": "router", "open_ports": [80]},
        {"ip": "192.168.1.120", "mac": "3C:22:FB:41:99:EE", "vendor": "Western Digital Technologies", "hostname": "MyCloud", "open_ports": [445]},
        {"ip": "192.168.1.135", "mac": "DC:A6:32:88:99:AA", "vendor": "Private Wi-Fi Address (likely a phone or tablet)", "hostname": "iPad", "open_ports": []},
        {"ip": "192.168.1.140", "mac": "F4:D4:88:12:34:56", "vendor": "Dell Inc", "hostname": "LAPTOP-4F2K", "open_ports": []},
    ],
    "Hardened home": [
        {"ip": "192.168.1.1", "mac": "00:14:D1:A2:88:01", "vendor": "ASUSTek Computer", "hostname": "RT-AX88U", "open_ports": []},
        {"ip": "192.168.1.102", "mac": "24:0A:C4:88:12:4A", "vendor": "Reolink Innovation", "hostname": "reolink-cam", "open_ports": []},
        {"ip": "192.168.1.110", "mac": "3C:22:FB:41:99:EE", "vendor": "Lenovo", "hostname": "ThinkPad-X1", "open_ports": []},
    ],
}

# -----------------------------------------------------------------------------
# 3. Helpers
# -----------------------------------------------------------------------------
ICONS = [("router", "📡"), ("gateway", "📡"), ("camera", "📷"), ("monitor", "👶"), ("nursery", "👶"),
         ("tv", "📺"), ("nas", "🗄️"), ("storage", "🗄️"), ("drive", "🗄️"), ("ipad", "📱"),
         ("laptop", "💻"), ("speaker", "🔊")]


def icon_for(vendor):
    v = vendor.lower()
    return next((i for k, i in ICONS if k in v), "🔌")


def status_color(s):
    return {"SECURE": C_OK, "WARNING": C_WARN, "HIGH RISK": C_BAD}.get(s, C_ACCENT)


def status_badge(s):
    cls = {"SECURE": "b-ok", "WARNING": "b-warn", "HIGH RISK": "b-bad"}.get(s, "b-ok")
    return f"<span class='badge {cls}'>{s}</span>"


def score_color(score):
    return C_OK if score >= 80 else (C_WARN if score >= 50 else C_BAD)


def ring_html(score, prev):
    circ = 502.65
    col = score_color(score)
    return (
        f"<div class='ring-wrap' style='--ringc:{col}'>"
        f"<svg width='230' height='230' viewBox='0 0 190 190'>"
        f"<circle class='ring-track' cx='95' cy='95' r='80' fill='none' stroke-width='10'/>"
        f"<circle class='ring-bar' cx='95' cy='95' r='80' fill='none' stroke='{col}' stroke-width='10' "
        f"style='--from:{circ * (1 - prev / 100):.2f};--to:{circ * (1 - score / 100):.2f}'/></svg>"
        f"<div class='ring-num'><b style='--nfrom:{prev};--nto:{score}'></b><span>out of 100</span></div></div>"
    )


def radar_html(devices):
    cx = cy = 200
    router_idx = next((i for i, d in enumerate(devices) if d["ip"].endswith(".1")), None)
    others = [d for i, d in enumerate(devices) if i != router_idx]
    parts = ["<svg viewBox='0 0 400 400' width='100%' style='max-width:440px;display:block;margin:auto'>"]
    for r in (50, 105, 160):
        parts.append(f"<circle cx='{cx}' cy='{cy}' r='{r}' fill='none' stroke='#16233A' stroke-width='1'/>")
    parts.append("<defs><linearGradient id='sw' x1='0' y1='0' x2='1' y2='0'>"
                 f"<stop offset='0' stop-color='{C_ACCENT}' stop-opacity='0'/>"
                 f"<stop offset='1' stop-color='{C_ACCENT}' stop-opacity='.35'/></linearGradient></defs>")
    parts.append(f"<g class='sweep'><path d='M200 200 L360 200 A160 160 0 0 0 322 97 Z' fill='url(#sw)'/></g>")
    n = max(len(others), 1)
    for i, d in enumerate(others):
        ang = (2 * math.pi * i / n) - math.pi / 2
        r = 120 if i % 2 == 0 else 150
        x, y = cx + r * math.cos(ang), cy + r * math.sin(ang)
        col = status_color(d["status"])
        parts.append(f"<line x1='{cx}' y1='{cy}' x2='{x:.1f}' y2='{y:.1f}' stroke='{col}' stroke-opacity='.25'/>")
        if d["status"] == "HIGH RISK":
            parts.append(f"<circle class='pulse' cx='{x:.1f}' cy='{y:.1f}' r='14' fill='{col}' fill-opacity='.25'/>")
        parts.append(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='8' fill='{col}'/>")
        label = d["vendor"].split("(")[0].strip()[:18]
        parts.append(f"<text x='{x:.1f}' y='{y + 24:.1f}' text-anchor='middle' fill='#9FB0C9' "
                     f"font-size='10' font-family='IBM Plex Mono'>{label}</text>")
    rc = status_color(devices[router_idx]["status"]) if router_idx is not None else C_ACCENT
    parts.append(f"<circle cx='{cx}' cy='{cy}' r='16' fill='#0B1220' stroke='{rc}' stroke-width='2'/>")
    parts.append(f"<text x='{cx}' y='{cy + 5}' text-anchor='middle' font-size='14'>📡</text></svg>")
    return "".join(parts)


def fix_port(ip, port):
    st.session_state["fixed_ports"].setdefault(ip, []).append(port)


def fix_all(queue):
    for item in queue:
        fix_port(item["ip"], item["port"])


def reset_fixes():
    st.session_state["fixed_ports"] = {}


MAX_SESSION_LABELS = 50


@st.cache_resource
def _base_classifier():
    # trained once and shared; it ignores any saved file so visitors never see each other's corrections
    return DeviceClassifier(user_labels=[])


def _session_classifier():
    """Public website: a classifier that includes only THIS visitor's corrections."""
    labels = st.session_state.get("session_labels", [])
    if not labels:
        return _base_classifier()
    version = st.session_state.get("_labels_version", 0)
    cached = st.session_state.get("_session_clf")
    if cached is None or cached[0] != version:
        cached = (version, DeviceClassifier(user_labels=labels))
        st.session_state["_session_clf"] = cached
    return cached[1]


def _active_classifier():
    return _session_classifier() if HOSTED else get_classifier()


def classify(device):
    return _session_classifier().classify(device) if HOSTED else classify_device(device)


def _reclassify_last_scan():
    raw = st.session_state.get("scan_raw", [])
    st.session_state["raw_devices"] = [{**_clean(x), "classification": classify(x)} for x in raw]


def teach(mac):
    """Save the user's correction for a device and re-run the classifier on the last scan."""
    label = st.session_state.get(f"teach_{mac}")
    raw = st.session_state.get("scan_raw", [])
    dev = next((x for x in raw if x.get("mac") == mac), None)
    if not dev or label not in DEVICE_META:
        return
    if HOSTED:  # this visit only
        rec = make_label_record(dev, label)
        labels = [u for u in st.session_state.get("session_labels", []) if u.get("mac") != rec["mac"]] + [rec]
        st.session_state["session_labels"] = labels[-MAX_SESSION_LABELS:]
        st.session_state["_labels_version"] = st.session_state.get("_labels_version", 0) + 1
    else:  # on your own computer: remembered in a file
        save_user_label(dev, label)
    _reclassify_last_scan()


def reset_taught():
    st.session_state["session_labels"] = []
    st.session_state["_labels_version"] = st.session_state.get("_labels_version", 0) + 1
    _reclassify_last_scan()


# -----------------------------------------------------------------------------
# 4. Sidebar
# -----------------------------------------------------------------------------
def _hosted():
    if os.environ.get("HOSTED_DEMO") == "1":
        return True
    try:
        return str(st.secrets.get("HOSTED_DEMO", "")) == "1"
    except Exception:
        return False


HOSTED = _hosted()
REPO_URL = "https://github.com/Vansh-Koundal/Cyber-House"
SCANNER_URL = REPO_URL + "/releases/latest"
ACTION = "Show results" if HOSTED else "Scan my network"


def _load_upload(f):
    """Read the scan file the user uploaded. Returns [] (and says why) if it is not usable."""
    try:
        f.seek(0)
        return parse_scan(f.read())
    except ScanFileError as err:
        st.sidebar.warning(str(err))
        return []


with st.sidebar:
    st.markdown("### 🛡️ Control panel")
    uploaded = None
    if HOSTED:
        scenario = st.selectbox("Sample home", list(MOCK_SCENARIOS.keys()),
                                help="Explore the dashboard with a made-up home.")
        st.markdown("<div class='consent'>🏠 <b>Check your own home?</b> A website cannot see inside your Wi-Fi, "
                    "so a small scanner runs on your computer and saves a file that you upload here.</div>",
                    unsafe_allow_html=True)
        st.link_button("1. Download the scanner", SCANNER_URL, use_container_width=True)
        st.caption("2. Run it on a computer connected to your home Wi-Fi.")
        uploaded = st.file_uploader("3. Upload cyberhouse_scan.json", type="json")
        st.caption("Your file is read for this session only and is not saved by this app.")
        use_demo = uploaded is None  # an uploaded file counts as a real scan, so permission is required
        subnet, depth = "", "Quick scan"
    else:
        use_demo = st.toggle("Demo mode", value=True, help="Use a sample home instead of scanning your real network.")
        scenario = st.selectbox("Sample home", list(MOCK_SCENARIOS.keys()), disabled=not use_demo)
        subnet = st.text_input("Network range", value=detect_subnet(), disabled=use_demo)
        depth = st.radio("Scan depth", ["Quick scan", "Deep scan"], horizontal=True, disabled=use_demo,
                         help="Quick checks 6 common risky ports. Deep checks 16 ports plus UPnP, security "
                              "certificates and Wi-Fi security, and takes longer.")
    tech = st.toggle("Show technical details", value=False, help="Adds ports, hardware addresses and device banners.")
    st.markdown("<div class='consent'>⚠️ Only scan networks you own or are allowed to test. "
                "Scanning other people's networks can be illegal.</div>", unsafe_allow_html=True)
    consent = st.checkbox("I own this network or have permission to scan it", key="consent",
                          help="Required for real scans. Demo mode does not touch your network.")
    scan = st.button(ACTION, use_container_width=True, type="primary",
                     disabled=(not use_demo and not consent))

st.session_state.setdefault("fixed_ports", {})
st.session_state.setdefault("prev_score", 0)
st.session_state.setdefault("shown_score", 0)

def _clean(d):
    # device names and banners come from the network, so make them safe to show as HTML
    return {**d, "vendor": html.escape(str(d.get("vendor", ""))), "banner": html.escape(str(d.get("banner", "")))[:160],
            "hostname": html.escape(str(d.get("hostname", "")))[:60]}


go = scan or st.session_state.pop("_go", False)
if go and not use_demo and not consent:
    st.sidebar.error("Please tick the permission box before scanning a real network.")
    go = False
if go:
    reset_fixes()
    st.session_state["prev_score"] = 0
    st.session_state["shown_score"] = 0
    deep = depth == "Deep scan"
    with st.spinner("Deep scan in progress. This can take a minute..." if (deep and not use_demo) else "Scanning your network..."):
        time.sleep(0.6)
        source = "sample"
        if uploaded is not None:
            raw = _load_upload(uploaded)
            if raw:
                source = "live"
            else:
                raw = MOCK_SCENARIOS[scenario]
        elif use_demo:
            raw = MOCK_SCENARIOS[scenario]
        else:
            raw = run_full_network_audit(ip_range=subnet, deep=deep)
            if raw:
                source = "live"
            else:
                st.sidebar.warning(get_last_error() or "No devices found. Showing the sample home instead.")
                raw = MOCK_SCENARIOS[scenario]
        st.session_state["source"] = source
        st.session_state["scan_raw"] = raw
        st.session_state["raw_devices"] = [{**_clean(d), "classification": classify(d)} for d in raw]

# -----------------------------------------------------------------------------
# 5. Main layout
# -----------------------------------------------------------------------------
if "raw_devices" not in st.session_state:
    preview = [
        {"ip": "192.168.1.1", "vendor": "Router", "status": "SECURE"},
        {"ip": "192.168.1.5", "vendor": "Camera", "status": "HIGH RISK"},
        {"ip": "192.168.1.6", "vendor": "Smart TV", "status": "WARNING"},
        {"ip": "192.168.1.7", "vendor": "Laptop", "status": "SECURE"},
        {"ip": "192.168.1.8", "vendor": "Speaker", "status": "SECURE"},
    ]
    l, r = st.columns([1.15, 1], gap="large")
    with l:
        st.markdown(
            "<p class='mono' style='color:#38D9FF;letter-spacing:.15em'>HOME NETWORK SCANNER</p>"
            "<p class='hero-grad'>Is your home network safe?</p>"
            "<p class='hero-sub'>See every connected device, find out what is exposed, and fix it "
            "step by step. No technical knowledge needed.</p>"
            "<div class='feat'><i>🧠</i><div><b>AI device recognition</b><span>Identifies cameras, TVs, speakers and more from their brand, name and open ports.</span></div></div>"
            "<div class='feat'><i>🗣️</i><div><b>Plain-English advice</b><span>Every risk explained like a friend would, with a clear fix.</span></div></div>"
            "<div class='feat'><i>📈</i><div><b>Watch your score climb</b><span>Fix issues and see your home safety score update live.</span></div></div>",
            unsafe_allow_html=True)
        st.write("")
        if st.button(ACTION, type="primary", use_container_width=True, disabled=not (use_demo or consent)):
            st.session_state["_go"] = True
            st.rerun()
        if not use_demo and not consent:
            st.caption("Real scans need your permission: tick the box in the sidebar first.")
    with r:
        st.markdown(f"<div class='panel'>{radar_html(preview)}</div>", unsafe_allow_html=True)
    st.stop()

fixed = st.session_state["fixed_ports"]
live = [{**d, "open_ports": [p for p in d["open_ports"] if p not in fixed.get(d["ip"], [])]}
        for d in st.session_state["raw_devices"]]
ev = calculate_health_index(live)
score, devices = ev["score"], ev["devices"]

# score animation bookkeeping: ring starts from whatever was last shown
prev = st.session_state["shown_score"]
st.session_state["shown_score"] = score

queue = []
for d in devices:
    for r in d["risks"]:
        trial = [{**x, "open_ports": [p for p in x["open_ports"]
                                      if not (x["ip"] == d["ip"] and p == r["port"])]} for x in live]
        gain = calculate_health_index(trial)["score"] - score
        queue.append({"ip": d["ip"], "vendor": d["vendor"], "port": r["port"], "name": r["name"],
                      "severity": r["severity"], "gain": gain, "deduction": r["deduction"],
                      "action": r["action"], "description": r["description"], "cls": d["classification"]})
queue.sort(key=lambda x: (-x["gain"], -x["deduction"]))

original = calculate_health_index(st.session_state["raw_devices"])["score"]
n_fixed = sum(len(v) for v in fixed.values())
high = sum(1 for d in devices if d["status"] == "HIGH RISK")

verdict = {"EXCELLENT": "Your home network looks healthy.",
           "NEEDS ATTENTION": "A few devices need attention.",
           "CRITICAL": "Some devices are exposed right now."}[ev["status"]]

src = "LIVE SCAN RESULTS" if st.session_state.get("source") == "live" else "SAMPLE DATA (NOT YOUR NETWORK)"
st.markdown(f"<p class='mono' style='color:#38D9FF;letter-spacing:.15em;margin:0'>{src}</p>", unsafe_allow_html=True)
st.markdown(f"<p class='hero-title'>{verdict}</p>"
            f"<p class='hero-sub'>{len(queue)} open issue{'s' if len(queue) != 1 else ''} across "
            f"{len(devices)} devices. Start with the top item in the Fix plan tab.</p>", unsafe_allow_html=True)

left, right = st.columns([1, 1.6], gap="large")
with left:
    st.markdown(f"<div class='panel' style='text-align:center'><div class='panel-title'>Home safety score</div>"
                f"{ring_html(score, prev)}<div style='margin-top:12px'>{status_badge('SECURE' if score >= 80 else ('WARNING' if score >= 50 else 'HIGH RISK'))}</div></div>",
                unsafe_allow_html=True)
with right:
    gain = score - original
    delta = f"+{gain} since scan" if gain > 0 else "No fixes applied yet"
    st.markdown(
        "<div class='panel'><div class='panel-title'>At a glance</div><div style='height:10px'></div>"
        f"<div class='stat'><b>{len(devices)}</b><span>devices on your network</span></div>"
        f"<div class='stat'><b style='color:{C_BAD if high else C_OK}'>{high}</b><span>devices at high risk</span></div>"
        f"<div class='stat'><b>{n_fixed}</b><span>issues fixed in this session ({delta})</span></div></div>",
        unsafe_allow_html=True)

st.markdown("<div style='height:18px'></div>", unsafe_allow_html=True)
t_map, t_fix, t_dev, t_rep = st.tabs(["Network map", "Fix plan", "All devices", "Report"])

# ---- Network map
with t_map:
    a, b = st.columns([1.2, 1], gap="large")
    with a:
        st.markdown(f"<div class='panel'>{radar_html(devices)}</div>", unsafe_allow_html=True)
    with b:
        st.markdown("<div class='panel'><div class='panel-title'>Reading the map</div>"
                    "<p class='muted'>Your router sits in the middle. Each dot is a device. "
                    "Pulsing red dots need action first.</p>"
                    f"<p><span class='badge b-ok'>SECURE</span> &nbsp;<span class='badge b-warn'>WARNING</span> &nbsp;"
                    f"<span class='badge b-bad'>HIGH RISK</span></p></div>", unsafe_allow_html=True)

# ---- Fix plan
with t_fix:
    h1, h2, h3 = st.columns([3, 1.2, 1])
    h1.markdown("<div class='panel-title'>Fix these in order</div>"
                "<p class='muted'>Biggest score gains first. Fixing here simulates the change so you can see the effect.</p>",
                unsafe_allow_html=True)
    h2.button("Fix everything", on_click=fix_all, args=(queue,), disabled=not queue, use_container_width=True, type="primary")
    h3.button("Undo all", on_click=reset_fixes, disabled=not fixed, use_container_width=True)

    if not queue:
        st.success("Nothing left to fix. Every scanned device is clear of risky open ports.")
    for i, q in enumerate(queue):
        sev = q["severity"]
        c1, c2 = st.columns([5, 1.3], vertical_alignment="center")
        extra = f" <span class='mono'>port {q['port']}</span>" if (tech and isinstance(q["port"], int)) else ""
        ex = explain_risk(q["cls"], q["vendor"], q["port"], sev)
        c1.markdown(
            f"<div class='risk {sev}'><h5>{q['cls']['icon']} {ex['title']}{extra}</h5>"
            f"<p class='mono'>{q['vendor']}  ·  +{q['gain']} points  ·  {ex['urgency']}  ·  about {ex['time']}</p>"
            f"<p>{ex['story']}</p>"
            f"<p><b>What to do:</b> {ex['fix']}</p></div>", unsafe_allow_html=True)
        c2.button("Mark as fixed", key=f"fix_{q['ip']}_{q['port']}", on_click=fix_port,
                  args=(q["ip"], q["port"]), use_container_width=True)

# ---- Devices
with t_dev:
    cols = st.columns(2, gap="medium")
    order = ["HIGH RISK", "WARNING", "SECURE"]
    for i, d in enumerate(sorted(devices, key=lambda x: order.index(x["status"]))):
        c = d["classification"]
        icon = "❓" if c["uncertain"] else c["icon"]
        if c.get("taught"):
            ai = f"You taught me: {c['label']}"
        elif c["uncertain"]:
            ai = f"AI is unsure: maybe {c['label']} or {c['top3'][1][0]}"
        else:
            ai = f"AI says: {c['label']} ({int(c['confidence'] * 100)}% sure)"
        detail = f"<div class='mono'>{d['ip']}" + (f"  ·  {d['mac']}" if tech else "") + "</div>"
        if d.get("hostname"):
            detail += f"<div class='mono'>Name: {d['hostname']}</div>"
        detail += f"<div class='mono' style='color:#38D9FF'>{ai}</div>"
        if tech and d.get("banner"):
            detail += f"<div class='mono'>Banner: {d['banner']}</div>"
        n = len(d["risks"])
        note = f"{n} issue{'s' if n != 1 else ''} found" if n else "No risky open ports"
        with cols[i % 2]:
            st.markdown(
                f"<div class='panel' style='margin-bottom:14px'><div class='dev-head'>"
                f"<div class='dev-ico'>{icon}</div>"
                f"<div style='flex:1'><div class='panel-title'>{d['vendor']}</div>{detail}</div>"
                f"{status_badge(d['status'])}</div>"
                f"<p class='muted' style='margin:12px 0 0'>{note}</p></div>", unsafe_allow_html=True)
    with st.expander("How the AI identified each device"):
        rep_ = model_report(_active_classifier())
        st.caption(f"Model: {rep_['algorithm']} · held-out accuracy on synthetic data: {rep_['holdout_accuracy']:.0%} · corrections taught by you: {rep_['user_labels']}")
        for d in devices:
            c = d["classification"]
            st.markdown(f"**{d['vendor']}** → {c['icon']} {c['label']} ({c['confidence']:.0%})")
            for reason in c["reasons"]:
                st.markdown(f"- Because {reason}")
            if c["note"]:
                st.caption(c["note"])
    if st.session_state.get("source") == "live" or HOSTED:
        with st.expander("Teach the AI (fix a wrong guess)", expanded=any(d["classification"]["uncertain"] for d in devices)):
            st.caption("Choose the right type and press Save. The AI learns from it right away. "
                       + ("On this website your corrections last for this visit only." if HOSTED
                          else "It is remembered on this computer."))
            types = list(DEVICE_META.keys())
            for d in devices:
                if not d.get("mac"):
                    continue
                a_, b_, e_ = st.columns([3, 3, 1.2], vertical_alignment="center")
                a_.markdown(f"**{d['vendor']}**  \n`{d['ip']}`" + (f"  ·  {d['hostname']}" if d.get("hostname") else ""))
                b_.selectbox("Device type", types, index=types.index(d["classification"]["label"]),
                             key=f"teach_{d['mac']}", label_visibility="collapsed")
                e_.button("Save", key=f"save_{d['mac']}", on_click=teach, args=(d["mac"],), use_container_width=True)
            if HOSTED and st.session_state.get("session_labels"):
                st.button("Forget my corrections", on_click=reset_taught)
    else:
        st.caption("Teaching the AI is available after a real scan.")

# ---- Report
with t_rep:
    st.markdown("<div class='panel'><div class='panel-title'>Family action report</div>"
                "<p class='muted'>A printable checklist with every device and what to do about it. "
                "Great for sharing with whoever manages the router.</p></div>", unsafe_allow_html=True)
    st.write("")
    st.download_button("Download report (PDF)", data=generate_pdf_report(ev),
                       file_name="Home_Cyber_Health_Report.pdf", mime="application/pdf")