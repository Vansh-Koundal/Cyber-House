# agent.py - CyberHouse Scanner
"""
Run this on a computer that is connected to your home Wi-Fi. It finds the devices on the network,
checks them for risky settings and saves a file that you upload to the CyberHouse website.
It only looks. It never changes anything on your devices.
"""
import os
import webbrowser

from scan_io import save_scan
from scanner import detect_subnet, get_last_error, run_full_network_audit

SITE = "https://cyber-house.streamlit.app"


def _output_path():
    home = os.path.expanduser("~")
    for folder in (os.path.join(home, "Desktop"), os.path.join(home, "OneDrive", "Desktop"), home):
        if os.path.isdir(folder):
            return os.path.join(folder, "cyberhouse_scan.json")
    return "cyberhouse_scan.json"


def main():
    print("=== CyberHouse Scanner ===")
    print("This checks the devices on the Wi-Fi this computer is connected to.")
    print("It only looks. It never changes anything.")
    print("Only continue on a network you own or have permission to test.\n")
    if input("Type YES and press Enter to continue: ").strip().upper() != "YES":
        print("Cancelled. Nothing was scanned.")
        return
    deep = input("Run a deep scan? It checks more but takes longer. (y/N): ").strip().lower() == "y"
    subnet = detect_subnet()
    print(f"\nScanning {subnet}. This usually takes 1-2 minutes, please wait.\n")
    devices = run_full_network_audit(subnet, deep=deep, progress=lambda msg: print("  - " + msg))
    if not devices:
        print("\nThe scan did not find any devices.")
        print(get_last_error() or "Check that you are connected to your home Wi-Fi and try again.")
        return
    path = _output_path()
    save_scan(devices, path, deep)
    print(f"\nDone. Found {len(devices)} devices.")
    print(f"Your results were saved to:\n  {path}\n")
    print("Your browser will open now. Upload that file on the page to see your results.")
    webbrowser.open(SITE)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # keep the window open so the person can read what went wrong
        print("\nSomething went wrong:", e)
    input("\nPress Enter to close this window.")
