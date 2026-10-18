@echo off
cd /d "%~dp0"
if not exist .venv (
    echo Setting up for the first time, this takes a minute or two...
    python -m venv .venv
)
call .venv\Scripts\activate
python -m pip install -q -r requirements.txt
python -m streamlit run app.py
pause
