#!/usr/bin/env bash
cd "$(dirname "$0")"
[ -d .venv ] || { echo "Setting up for the first time..."; python3 -m venv .venv; }
source .venv/bin/activate
python -m pip install -q -r requirements.txt
python -m streamlit run app.py
