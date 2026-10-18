# aiml_engine.py
"""
AI/ML engine for the Household Cyber Health Dashboard.

Part 1: DeviceClassifier
    Predicts what kind of device something is from three signals:
      - its open-port signature (which of the scanned ports respond)
      - its vendor / OUI / label text (character n-grams, so "Hikvision" and
        "Hikvision Digital" look alike)
      - optional response characteristics, e.g. a service banner (device["banner"])
    Model: TF-IDF + multi-hot ports -> multinomial Logistic Regression.
    It is lightweight (trains in well under a second), returns calibrated-ish
    probabilities, and is explainable: every prediction comes with the signals
    that pushed it toward that label.
"""
import json
import os
import random

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

SEED = 42
PORTS = [21, 23, 80, 445, 554, 8080]
CONFIDENCE_FLOOR = 0.45  # below this we say "best guess" instead of asserting a type

# Chip makers appear inside almost every kind of gadget, so their name says little about the device.
CHIP_VENDORS = ["AzureWave Technology", "Realtek Semiconductor", "MediaTek", "Murata Manufacturing",
                "Liteon Technology", "Hon Hai Precision", "Ralink Technology", "Qualcomm Atheros",
                "Texas Instruments", "Shenzhen Chipset Co"]
CHIP_KEYWORDS = ("azurewave", "realtek", "mediatek", "murata", "liteon", "lite-on", "hon hai",
                 "ralink", "qualcomm", "texas instruments", "shenzhen")

LABELS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "user_labels.json")
USER_LABEL_WEIGHT = 12  # a correction from the user counts like this many synthetic examples
PRIVATE_TEXT = "Private Wi-Fi Address (likely a phone or tablet)"
PRIVATE_RATE = {"Phone / Tablet": 0.70, "Work Laptop / PC": 0.20}  # chance a device uses a randomised MAC

# Typical device names (hostnames) per type, used to synthesise training data
HOSTS = {
    "Smart Security Camera": ["IPC", "ipcam", "camera", "hikvision-cam", "DS-2CD", "reolink", "wyze-cam", "tapo-c200"],
    "Baby Monitor": ["babycam", "nursery-cam", "nanit", "owlet", "baby-monitor"],
    "Smart TV": ["Samsung-TV", "LGwebOSTV", "BRAVIA", "Chromecast", "roku", "AndroidTV", "Fire-TV", "TV"],
    "Router / Gateway": ["router", "gateway", "dlinkrouter", "tplinkwifi", "RT-AX88U", "mikrotik", "modem"],
    "NAS / Shared Storage": ["DiskStation", "nas", "qnap", "MyCloud", "storage"],
    "Smart Speaker": ["Echo-Dot", "Google-Home-Mini", "HomePod", "sonos", "alexa", "speaker"],
    "IoT Smart Plug": ["ESP_", "tasmota", "shelly1", "smartplug", "tuya", "HS103", "wemo"],
    "Work Laptop / PC": ["DESKTOP-", "LAPTOP-", "MacBook-Pro", "Dell-XPS", "ThinkPad", "HP-Laptop", "windows-pc"],
    "Phone / Tablet": ["iPhone", "iPad", "Galaxy-S21", "Galaxy-Tab", "android-", "Pixel-7", "Redmi-Note", "OnePlus"],
}

PORT_PHRASE = {
    21: "a file-transfer (FTP) port is open",
    23: "a remote-login (Telnet) port is open",
    80: "a web control page is open",
    445: "shared-folder sharing is open",
    554: "a live video-stream port is open",
    8080: "a second web admin page is open",
}

# label -> (emoji, sensitive?)  "sensitive" = sees/hears inside the home
DEVICE_META = {
    "Smart Security Camera": ("📷", True),
    "Baby Monitor": ("👶", True),
    "Smart TV": ("📺", False),
    "Router / Gateway": ("📡", False),
    "NAS / Shared Storage": ("🗄️", True),
    "Smart Speaker": ("🔊", True),
    "IoT Smart Plug": ("🔌", False),
    "Work Laptop / PC": ("💻", False),
    "Phone / Tablet": ("📱", False),
}

# Behavioural profiles used to synthesise training data.
# ports: probability that the port is open for this device type.
PROFILES = {
    "Smart Security Camera": {
        "ports": {554: .90, 80: .50, 23: .35, 8080: .30, 21: .05},
        "vendors": ["Hikvision", "Dahua Technology", "Espressif Inc", "Reolink", "Amcrest",
                    "Wyze Labs", "IP Camera", "Security Camera", "Arlo", "Ring", "TP-Link Tapo"]},
    "Baby Monitor": {
        "ports": {554: .85, 23: .40, 80: .45, 8080: .20},
        "vendors": ["Baby Monitor", "Nanit", "Owlet", "Infant Optics", "Smart Nursery Camera",
                    "Motorola Nursery", "Cubo AI", "Smart Baby Monitor Camera"]},
    "Smart TV": {
        "ports": {8080: .60, 80: .30, 21: .20},
        "vendors": ["Samsung Electronics", "LG Electronics", "Sony", "TCL", "Hisense",
                    "Roku", "Vizio", "Smart TV", "Amazon Fire TV", "Xiaomi TV"]},
    "Router / Gateway": {
        "ports": {80: .95, 8080: .35, 23: .10, 21: .05},
        "vendors": ["TP-Link", "Netgear", "ASUSTek", "Linksys", "D-Link", "Ubiquiti",
                    "Huawei", "MikroTik", "Home Router", "Gateway Router", "Secure Gateway"]},
    "NAS / Shared Storage": {
        "ports": {445: .95, 21: .50, 80: .50, 8080: .30},
        "vendors": ["Synology", "QNAP", "Western Digital", "Seagate", "NAS Network Drive",
                    "Shared Storage Drive", "Network Drive", "Buffalo"]},
    "Smart Speaker": {
        "ports": {8080: .50, 80: .15},
        "vendors": ["Amazon Technologies", "Sonos", "Google", "Apple HomePod", "Smart Speaker",
                    "Bose", "Smart Nursery Speaker", "Harman"]},
    "IoT Smart Plug": {
        "ports": {80: .50, 23: .10, 8080: .10},
        "vendors": ["Espressif Inc", "TP-Link Kasa", "Tuya Smart", "Shelly", "Smart Plug",
                    "Belkin Wemo", "Gosund", "Meross"]},
    "Work Laptop / PC": {
        "ports": {445: .55},
        "vendors": ["Dell", "Lenovo", "HP Inc", "Intel Corporate", "Microsoft", "Apple",
                    "Liteon", "Realtek", "Work Laptop", "Personal Laptop", "Desktop PC"]},
    "Phone / Tablet": {
        "ports": {},
        "vendors": ["Apple", "Samsung Electronics", "Xiaomi", "OnePlus", "Google Pixel",
                    "Apple iPad", "iPhone", "Tablet", "Huawei Device", "OPPO"]},
}

_PREFIXES = ["", "", "", "Living Room ", "Kitchen ", "Bedroom ", "Office "]
_SUFFIXES = ["", "", " Inc", " Co., Ltd", " Technologies", " Corporation"]


def _port_features(port_lists):
    """Multi-hot over PORTS plus a 'many ports open' signal."""
    m = np.zeros((len(port_lists), len(PORTS) + 1))
    for i, ports in enumerate(port_lists):
        for p in ports:
            if p in PORTS:
                m[i, PORTS.index(p)] = 1.0
        m[i, -1] = min(sum(p in PORTS for p in ports), 4) / 4.0
    return m


def _device_text(device):
    return (f"{device.get('vendor', '')} {device.get('hostname', '')} {device.get('banner', '')}".strip()
            or "unknown vendor")


class DeviceClassifier:
    def __init__(self, seed=SEED, samples_per_class=90):
        self._rng = random.Random(seed)
        ports, texts, labels = self._synthesise(samples_per_class)
        Xp_tr, Xp_te, t_tr, t_te, y_tr, y_te = train_test_split(
            ports, texts, labels, test_size=0.2, random_state=seed, stratify=labels)

        # Human-in-the-loop: corrections the user saved are added to the training set
        self.user_labels = load_user_labels()
        self.user_by_mac = {u["mac"].lower(): u["label"] for u in self.user_labels if u.get("mac")}
        Xp_tr, t_tr, y_tr = list(Xp_tr), list(t_tr), list(y_tr)
        for u in self.user_labels:
            for _ in range(USER_LABEL_WEIGHT):
                Xp_tr.append(u.get("open_ports", []))
                t_tr.append(_device_text(u))
                y_tr.append(u["label"])

        self.tfidf = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                                     lowercase=True, sublinear_tf=True)
        X_tr = hstack([csr_matrix(_port_features(Xp_tr) * 1.5), self.tfidf.fit_transform(t_tr)]).tocsr()
        self.model = LogisticRegression(C=10, max_iter=3000, random_state=seed)
        self.model.fit(X_tr, y_tr)

        X_te = hstack([csr_matrix(_port_features(Xp_te) * 1.5), self.tfidf.transform(t_te)]).tocsr()
        self.holdout_accuracy = float(self.model.score(X_te, y_te))
        self.n_train = len(y_tr)
        self.feature_names = ([f"port:{p}" for p in PORTS] + ["port:count"]
                              + list(self.tfidf.get_feature_names_out()))

    # -- training data ---------------------------------------------------
    def _synthesise(self, n):
        ports, texts, labels = [], [], []
        for label, prof in PROFILES.items():
            count = int(n * 1.6) if label == "Work Laptop / PC" else n  # laptops are the most common home device
            for _ in range(count):
                open_ports = [p for p, pr in prof["ports"].items() if self._rng.random() < pr]
                if self._rng.random() < 0.08:  # stray open port noise
                    open_ports.append(self._rng.choice(PORTS))
                pool = prof["vendors"] + (CHIP_VENDORS if self._rng.random() < 0.3 else [])
                vendor = self._rng.choice(pool)
                r = self._rng.random()
                p_private = PRIVATE_RATE.get(label, 0.02)
                if r < p_private:
                    vendor = PRIVATE_TEXT
                elif r < p_private + 0.12:
                    vendor = "Unknown Vendor"
                text = self._rng.choice(_PREFIXES) + vendor + self._rng.choice(_SUFFIXES)
                if self._rng.random() < 0.55:  # many devices also reveal a hostname
                    text += " " + self._rng.choice(HOSTS[label]) + self._rng.choice(["", "", "-%04x" % self._rng.randrange(65536)])
                ports.append(sorted(set(open_ports)))
                texts.append(text)
                labels.append(label)
        return ports, texts, labels

    # -- inference -------------------------------------------------------
    def classify(self, device):
        mac = (device.get("mac") or "").lower()
        if mac in self.user_by_mac:  # the user already told us what this device is
            label = self.user_by_mac[mac]
            icon, sensitive = DEVICE_META[label]
            return {"label": label, "confidence": 1.0, "uncertain": False, "note": "", "taught": True,
                    "top3": [(label, 1.0)], "reasons": ["you told me this one earlier"],
                    "icon": icon, "sensitive": sensitive}
        ports = device.get("open_ports", [])
        text = _device_text(device)
        row = hstack([csr_matrix(_port_features([ports]) * 1.5), self.tfidf.transform([text])]).tocsr()

        proba = self.model.predict_proba(row)[0]
        order = np.argsort(proba)[::-1]
        classes = self.model.classes_
        best = classes[order[0]]
        conf = float(proba[order[0]])

        # Explainability: contribution of each feature = weight * value
        dense = row.toarray()[0]
        contrib = self.model.coef_[order[0]] * dense
        reasons = []
        for idx in np.argsort(contrib)[::-1][:len(PORTS) + 1]:
            if contrib[idx] < 0.3:
                break
            name = self.feature_names[idx]
            if name.startswith("port:") and name != "port:count":
                reasons.append((PORT_PHRASE[int(name[5:])], float(contrib[idx])))
        text_score = float(contrib[len(PORTS) + 1:].sum())
        if text_score > 0.3 and "unknown" not in text.lower():
            reasons.append((f"the name “{device.get('vendor', '')}” is typical for this kind of device", text_score))
        reasons.sort(key=lambda r: -r[1])

        vendor_l = (device.get("vendor") or "").lower()
        is_chip = any(k in vendor_l for k in CHIP_KEYWORDS) and not device.get("banner")
        no_info = (("unknown" in vendor_l or not vendor_l) and not device.get("hostname")
                   and not device.get("banner") and not any(p in PORTS for p in ports))
        uncertain = conf < CONFIDENCE_FLOOR or is_chip or no_info  # weak clues -> admit we are unsure
        note = ("This brand makes Wi-Fi chips used inside many kinds of gadgets, so its name alone is not a clue."
                if is_chip else "")
        if no_info_pre(device, ports):
            note = "There were no clues to go on (no brand, name or open ports), so this is only a guess."
        icon, sensitive = DEVICE_META[best]
        return {
            "label": str(best),
            "confidence": round(conf, 3),
            "uncertain": uncertain,
            "note": note,
            "taught": False,
            "top3": [(str(classes[i]), round(float(proba[i]), 3)) for i in order[:3]],
            "reasons": [r[0] for r in reasons[:3]],
            "icon": icon,
            "sensitive": sensitive,
        }


_CLASSIFIER = None


def get_classifier():
    """Train once, reuse everywhere."""
    global _CLASSIFIER
    if _CLASSIFIER is None:
        _CLASSIFIER = DeviceClassifier()
    return _CLASSIFIER


def no_info_pre(device, ports):
    vendor_l = (device.get("vendor") or "").lower()
    return (("unknown" in vendor_l or not vendor_l) and not device.get("hostname")
            and not device.get("banner") and not any(p in PORTS for p in ports))


def load_user_labels():
    try:
        with open(LABELS_PATH) as f:
            return [u for u in json.load(f) if u.get("label") in DEVICE_META]
    except Exception:
        return []


def reset_classifier():
    global _CLASSIFIER
    _CLASSIFIER = None


def save_user_label(device, label):
    """Remember a correction from the user and retrain on next use."""
    rec = {"mac": (device.get("mac") or "").lower(), "vendor": device.get("vendor", ""),
           "hostname": device.get("hostname", ""), "banner": device.get("banner", ""),
           "open_ports": [p for p in device.get("open_ports", []) if isinstance(p, int)], "label": label}
    labels = [u for u in load_user_labels() if u.get("mac") != rec["mac"]] + [rec]
    with open(LABELS_PATH, "w") as f:
        json.dump(labels, f, indent=2)
    reset_classifier()


def classify_device(device):
    return get_classifier().classify(device)


def model_report():
    c = get_classifier()
    return {"algorithm": "TF-IDF (character n-grams) + port signature → Logistic Regression",
            "classes": [str(x) for x in c.model.classes_], "train_samples": c.n_train,
            "holdout_accuracy": round(c.holdout_accuracy, 3), "user_labels": len(c.user_labels)}


# =============================================================================
# Part 2: Plain-English Explainer
#   explain_risk()  - offline template engine that adapts to the device type the
#                     classifier predicted (always works, safe for live demos)
#   llm_explain()   - optional LLM rewrite in a friendly "cyber expert talking to
#                     a parent" voice; returns None if no key / no internet so the
#                     caller can fall back to the template.
# =============================================================================
import os
import re

import requests

# label -> (short noun, why this device matters)
ROLE = {
    "Smart Security Camera": ("camera", "It can see inside your home, so it is worth locking down properly."),
    "Baby Monitor": ("baby monitor", "It watches over your little one, so this is one to fix first."),
    "Smart TV": ("TV", "It is not watching anything private, but a weak spot here can be a way into the rest of your network."),
    "Router / Gateway": ("router", "It is the front door to your whole home network, so everything else depends on it."),
    "NAS / Shared Storage": ("shared drive", "It holds your family's files and photos."),
    "Smart Speaker": ("speaker", "It has a microphone in your home."),
    "IoT Smart Plug": ("smart plug", "It is small, but cheap gadgets like this are a favourite way in for attackers."),
    "Work Laptop / PC": ("laptop", "It may hold work files and saved passwords."),
    "Phone / Tablet": ("tablet", "It carries your messages, photos and logins."),
}
GENERIC_ROLE = ("device", "Anything on your Wi-Fi can be a way in if it is left unprotected.")

# port -> (title, what is wrong, how to fix, time to fix)
PORT_STORY = {
    21: ("files sent unprotected",
         "sends files across your Wi-Fi without scrambling them, so someone on the same network could read them",
         "Open its settings and switch off “FTP”. If you still need to move files, use the secure option (SFTP) instead.",
         "5 minutes"),
    23: ("open remote login",
         "has an old-style remote login switched on, and anyone nearby could pick up the password as it is typed",
         "In its settings, turn off “Telnet”. If there is no such option, check its app for a firmware update.",
         "5 minutes"),
    80: ("unprotected settings page",
         "has a settings page that is not scrambled, so a password typed there could be spied on from the same Wi-Fi",
         "Turn on “HTTPS” in its settings, and only log in from your own phone or laptop on your home Wi-Fi.",
         "5 minutes"),
    445: ("shared folders open",
          "shares folders across your network, so other devices at home may be able to browse them",
          "Check every shared folder has a password, or switch sharing off for the ones you do not use.",
          "10 minutes"),
    554: ("live video exposed",
          "streams video over your network with only light protection",
          "Open its settings and set a new, unique password. Do not keep the one it came with.",
          "3 minutes"),
    8080: ("extra settings page open",
           "has a second settings page open, and these often still use a factory login like admin / admin",
           "Change the default login. Try admin / admin yourself: if it works, an attacker can do the same.",
           "5 minutes"),
}
PORT_STORY.update({
    22: ("remote-access door open", "has a secure remote-access service (SSH) switched on, which is fine if you use it but a target if its password is weak",
         "If you do not use remote access, switch “SSH” off in its settings. If you do, make sure it uses a strong password or a key.", "5 minutes"),
    139: ("old file sharing open", "has an old Windows file-sharing service switched on that can reveal device names and shared folders",
          "Turn off “NetBIOS” or old file sharing in its network settings if you do not need it.", "5 minutes"),
    1883: ("smart-home messaging open", "has a smart-home messaging service (MQTT) open that often needs no password at all",
           "Set a username and password on the hub or MQTT service, or switch it off if you do not use it.", "10 minutes"),
    3389: ("remote desktop open", "lets someone take over its screen remotely if they guess the password, a favourite target for attackers",
           "Turn off “Remote Desktop” in Windows settings unless you really need it, and never expose it to the internet.", "5 minutes"),
    5555: ("developer back door open", "has a developer debugging door (ADB) open, which can let anyone on your Wi-Fi install apps or take control",
           "In its settings, turn off “USB debugging” or “ADB over network” under Developer options.", "5 minutes"),
    5900: ("screen sharing open", "has screen sharing (VNC) switched on, often with a weak or missing password",
           "Turn off screen sharing in its settings, or set a strong password on it.", "5 minutes"),
    7547: ("router remote-management open", "has a remote-management service (TR-069) open, which has been used in large attacks on home routers",
           "Open the router's admin page, turn off “remote management” or “TR-069”, and update its firmware.", "10 minutes"),
    9100: ("printer open to anyone", "accepts print jobs from any device on your network without a login",
           "Check the printer's settings for access control, or turn off “raw printing” if you do not use it.", "10 minutes"),
    "upnp": ("automatic port opening (UPnP) on", "lets other devices open doors in your router on their own, without asking you",
             "Turn off “UPnP” in your router's settings unless a game or app really needs it.", "5 minutes"),
    "cert_expired": ("expired security certificate", "has a web page whose security certificate has expired, so browsers cannot trust it",
                     "Check for a firmware update, or renew the certificate in its settings.", "10 minutes"),
    "cert_selfsigned": ("unverified security certificate", "uses a home-made security certificate, so a browser cannot prove who it is",
                        "This is common and low-risk at home. Install firmware updates and log in only from your own devices.", "10 minutes"),
    "wifi_open": ("Wi-Fi has no password", "is sending out a Wi-Fi network with no password, so anyone in range can join it and watch the traffic",
                  "Log in to the router, open Wireless settings and set security to WPA2 or WPA3 with a strong password.", "10 minutes"),
    "wifi_weak": ("Wi-Fi uses outdated security", "is using outdated Wi-Fi security (WEP or WPA1), which can be broken in minutes",
                  "Log in to the router, open Wireless settings and switch security to WPA2 or WPA3.", "10 minutes"),
})
URGENCY = {"HIGH": "Fix today", "MEDIUM": "Fix this week", "LOW": "Fix when you can"}


def _nickname(cls, vendor):
    noun = GENERIC_ROLE[0] if cls.get("uncertain") else ROLE[cls["label"]][0]
    room = re.search(r"(living room|kitchen|bedroom|office|nursery|garage)", vendor or "", re.I)
    return f"{room.group(1).lower()} {noun}" if room else noun


def explain_risk(cls, vendor, port, severity):
    """Template explainer. cls is the dict returned by classify_device()."""
    title, what, fix, minutes = PORT_STORY.get(
        port, ("open port", "has a door open that it does not need", "Check its settings for options you do not use and turn them off.", "10 minutes"))
    nick = _nickname(cls, vendor)
    role = GENERIC_ROLE if cls.get("uncertain") else ROLE[cls["label"]]
    if port == 554 and cls.get("label") not in ("Smart Security Camera", "Baby Monitor"):
        what = "streams video or audio over your network with only light protection"
    story = f"Your {nick} {what}. {role[1]}"
    return {"title": f"{nick.capitalize()}: {title}", "story": story, "fix": fix,
            "time": minutes, "urgency": URGENCY.get(severity, "Fix when you can"), "source": "template"}


LLM_MODEL = os.environ.get("AIML_LLM_MODEL", "claude-sonnet-5-5")
LLM_SYSTEM = (
    "You are a friendly cybersecurity expert explaining a home-network finding to a busy, non-technical parent. "
    "Use warm, plain language with no jargon and no scare tactics. Write at most 3 short sentences: what is "
    "happening, why it matters for the family, and the first thing to do. Do not use bullet points or headings."
)


def llm_available():
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def llm_explain(cls, vendor, port, port_name, severity):
    """Returns a friendly LLM-written explanation, or None so the caller can fall back to the template."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    base = explain_risk(cls, vendor, port, severity)
    prompt = (f"Device: {vendor} (identified as: {cls['label']}).\n"
              f"Finding: {port_name} on port {port}, severity {severity}.\n"
              f"Plain facts: {base['story']} Suggested fix: {base['fix']}\n"
              "Rewrite this for the parent.")
    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": LLM_MODEL, "max_tokens": 300, "system": LLM_SYSTEM,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=15)
        r.raise_for_status()
        text = "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text").strip()
        return text or None
    except Exception:
        return None


if __name__ == "__main__":
    print(model_report())
    demo = [
        {"vendor": "Espressif Inc (Living Room IP Camera)", "open_ports": [23, 554]},
        {"vendor": "Samsung Smart TV", "open_ports": [21, 8080]},
        {"vendor": "Hikvision Digital", "open_ports": [554, 80]},
        {"vendor": "Espressif Inc", "open_ports": [80]},
        {"vendor": "Unknown Vendor", "open_ports": []},
    ]
    for d in demo:
        r = classify_device(d)
        print(d["vendor"], d["open_ports"], "->", r["label"], r["confidence"], r["reasons"])
        for p in d["open_ports"][:1]:
            print("   ", explain_risk(r, d["vendor"], p, "HIGH")["story"])  