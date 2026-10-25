# apply_teach_patch.py
# Run once from your project folder:  python apply_teach_patch.py
# Makes "Teach the AI" work on the public website: corrections are kept per visitor (this visit only),
# so they can never affect other people. On your own computer it still remembers corrections in a file.
# It edits aiml_engine.py and app.py, saves copies as *.before_teach, and stops without changes if anything looks off.
import os
import shutil
import sys


def rd(p):
    with open(p, encoding="utf-8", newline="") as f:
        return f.read().replace("\r\n", "\n")


def wr(p, s):
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)


def once(s, old, new, label):
    n = s.count(old)
    if n != 1:
        sys.exit(f"STOPPED: could not find the expected text for '{label}' (found {n} times). Nothing was changed.")
    return s.replace(old, new)


for need in ("aiml_engine.py", "app.py"):
    if not os.path.exists(need):
        sys.exit(f"STOPPED: {need} not found. Run this from your project folder.")

a, p = rd("aiml_engine.py"), rd("app.py")
if "def _session_classifier" in p or "make_label_record" in a:
    sys.exit("This patch is already applied. Nothing to do.")

# ---------------------------------------------------------------- aiml_engine.py
a = once(a, "def __init__(self, seed=SEED, samples_per_class=90):",
         "def __init__(self, seed=SEED, samples_per_class=90, user_labels=None):", "classifier signature")
a = once(a, "        self.user_labels = load_user_labels()\n",
         "        self.user_labels = load_user_labels() if user_labels is None else list(user_labels)\n", "classifier labels")
a = once(a, '''def save_user_label(device, label):
    """Remember a correction from the user and retrain on next use."""
    rec = {"mac": (device.get("mac") or "").lower(), "vendor": device.get("vendor", ""),
           "hostname": device.get("hostname", ""), "banner": device.get("banner", ""),
           "open_ports": [p for p in device.get("open_ports", []) if isinstance(p, int)], "label": label}
''', '''def make_label_record(device, label):
    """The training example for one correction from the user."""
    return {"mac": (device.get("mac") or "").lower(), "vendor": device.get("vendor", ""),
            "hostname": device.get("hostname", ""), "banner": device.get("banner", ""),
            "open_ports": [p for p in device.get("open_ports", []) if isinstance(p, int)], "label": label}


def save_user_label(device, label):
    """Remember a correction from the user (on this computer) and retrain on next use."""
    rec = make_label_record(device, label)
''', "save_user_label")
a = once(a, "def model_report():\n    c = get_classifier()\n", "def model_report(clf=None):\n    c = clf or get_classifier()\n", "model_report")
wr("aiml_engine.py.new", a)

# ---------------------------------------------------------------- app.py
p = once(p, "from aiml_engine import classify_device, model_report, explain_risk, save_user_label, DEVICE_META",
         "from aiml_engine import (classify_device, model_report, explain_risk, save_user_label, make_label_record,\n"
         "                         get_classifier, DeviceClassifier, DEVICE_META)", "app import")

start = p.index("def teach(mac):")
end = p.index("# -----------------------------------------------------------------------------\n# 4. Sidebar")
new_teach = '''MAX_SESSION_LABELS = 50


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


'''
p = p[:start] + new_teach + p[end:]

p = once(p, '"classification": classify_device(d)} for d in raw]', '"classification": classify(d)} for d in raw]', "scan classification")
p = once(p, "rep_ = model_report()", "rep_ = model_report(_active_classifier())", "model report")

marker_start = '    if st.session_state.get("source") == "live" and not HOSTED:'
marker_end = 'st.caption("Teaching the AI is available after a real scan.")'
s = p.index(marker_start)
e = p.index(marker_end, s) + len(marker_end)
new_block = '''    if st.session_state.get("source") == "live" or HOSTED:
        with st.expander("Teach the AI (fix a wrong guess)", expanded=any(d["classification"]["uncertain"] for d in devices)):
            st.caption("Choose the right type and press Save. The AI learns from it right away. "
                       + ("On this website your corrections last for this visit only." if HOSTED
                          else "It is remembered on this computer."))
            types = list(DEVICE_META.keys())
            for d in devices:
                if not d.get("mac"):
                    continue
                a_, b_, e_ = st.columns([3, 3, 1.2], vertical_alignment="center")
                a_.markdown(f"**{d['vendor']}**  \\n`{d['ip']}`" + (f"  ·  {d['hostname']}" if d.get("hostname") else ""))
                b_.selectbox("Device type", types, index=types.index(d["classification"]["label"]),
                             key=f"teach_{d['mac']}", label_visibility="collapsed")
                e_.button("Save", key=f"save_{d['mac']}", on_click=teach, args=(d["mac"],), use_container_width=True)
            if HOSTED and st.session_state.get("session_labels"):
                st.button("Forget my corrections", on_click=reset_taught)
    else:
        st.caption("Teaching the AI is available after a real scan.")'''
p = p[:s] + new_block + p[e:]

for f in ("aiml_engine.py", "app.py"):
    shutil.copy(f, f + ".before_teach")
os.replace("aiml_engine.py.new", "aiml_engine.py")
wr("app.py", p)
print("Done. Backups saved as aiml_engine.py.before_teach and app.py.before_teach.")
print("Next: python -m py_compile app.py aiml_engine.py")
