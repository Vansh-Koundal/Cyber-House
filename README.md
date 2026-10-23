# 🛡️ Household Cyber Health Dashboard

A friendly network safety checker for families. It scans your home network, works out what each device is using a small machine-learning model, explains every risk in plain English, and lets you watch your **Home Safety Score** climb as you fix things.

Built for STOGOFEST.

<!-- Add screenshots here: ![Dashboard](docs/dashboard.png) -->
<img width="1535" height="693" alt="image" src="https://github.com/user-attachments/assets/c6f0e87b-6956-4afd-92a6-8d2cf4a2023d" />

## What it does

- **Finds every device** on your Wi-Fi (ARP discovery) and checks it for risky open ports.
- **Deep scan** adds UPnP, security-certificate and Wi-Fi-security checks.
- **AI device recognition:** a scikit-learn model guesses what each device is (camera, TV, router, laptop…) from its brand, name, open ports and service banners. It says "unsure" when it has no clues.
- **Teach the AI:** correct a wrong guess and the model remembers it and retrains.
- **Plain-English advice** for every finding, with a time estimate and a fix.
- **What-if fixing:** mark an issue as fixed and the score updates live.
- **Printable PDF report** for the family.

## Quick start

You need **Python 3.10 or newer** ([python.org](https://www.python.org/downloads/), tick "Add Python to PATH" on Windows).

**Windows:** download this project as a ZIP, unzip it, and double-click `run.bat`.
**Mac / Linux:** open a terminal in the folder and run `bash run.sh`.

The first launch installs the libraries (a minute or two), then your browser opens the dashboard. **Demo mode is on by default**, so you can explore sample homes without touching your network.

## Scanning your real network

1. **Windows only:** install [Npcap](https://npcap.com) (tick "WinPcap API-compatible mode").
2. Run the app as **Administrator** (right-click `run.bat` → Run as administrator). On Mac/Linux use `sudo bash run.sh`.
3. In the sidebar, turn **Demo mode** off, tick the **permission checkbox**, pick Quick or Deep scan, and press **Scan my network**.

> ⚠️ **Only scan networks you own or have permission to test.** Scanning other people's networks can be illegal.

## Hosted demo

A hosted version (sample homes only) can be deployed free on Streamlit Community Cloud. Set the secret `HOSTED_DEMO = "1"` so real scanning and the Teach panel are switched off there. A cloud server cannot see your home network.

## How it works

| File | Job |
|---|---|
| `app.py` | Streamlit dashboard, score ring, network map, fix plan, guide |
| `scanner.py` | ARP discovery, port scan, banner grabbing, UPnP / certificate / Wi-Fi checks |
| `aiml_engine.py` | Device classifier (TF-IDF + port signature → Logistic Regression) and the plain-English explainer |
| `evaluator.py` + `risk_db.json` | Turns open ports and findings into risks and the 0–100 score |
| `pdf_generator.py` | Printable family report |

## About the AI, honestly

- The classifier is trained on **synthetic data** generated from typical device profiles, plus any corrections you teach it. Its accuracy on synthetic data is not the same as accuracy on real homes.
- Wi-Fi chip makers (e.g. AzureWave, Realtek) are treated as uninformative, and devices with no clues are labelled "unsure" rather than guessed.
- The explainer is **rule-based templates**, not a language model.
- The score is a guide, not a guarantee. An open port is not always a vulnerability.

## Limitations

- Checks about 16 ports plus a few home-specific checks. It is **not** a CVE or vulnerability-database scanner.
- The Wi-Fi security check works on Windows with English settings, when the PC is on Wi-Fi.
- "Mark as fixed" simulates the change. Fix the real device, then scan again to confirm.

## License

MIT. See `LICENSE`.
