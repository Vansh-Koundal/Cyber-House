import csv
import aiml_engine as m

m.LABELS_PATH = "no_such_file.json"  # ignore any labels you taught it
c = m.DeviceClassifier()
valid = set(m.DEVICE_META)
ok = n = skipped = 0
for row in csv.DictReader(open("real_devices.csv", encoding="utf-8")):
    label = row["true_label"].strip()
    if not label:
        skipped += 1
        continue
    if label not in valid:
        print("BAD LABEL (typo?):", repr(label), "| row:", row["vendor"])
        continue
    ports = [int(p) for p in row["ports"].split(";") if p]
    r = c.classify({"vendor": row["vendor"], "hostname": row["hostname"],
                    "open_ports": ports, "banner": "", "mac": ""})
    hit = r["label"] == label
    ok += hit
    n += 1
    print("OK  " if hit else "MISS", "|", row["vendor"], "| host:", row["hostname"] or "-",
          "| ports:", row["ports"] or "-", "| you said:", label,
          "| model:", r["label"], r["confidence"], "(unsure)" if r["uncertain"] else "")
print(f"Real-device accuracy: {ok}/{n}  (skipped {skipped} unlabelled rows)")