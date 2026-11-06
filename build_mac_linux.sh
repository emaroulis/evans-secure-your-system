#!/usr/bin/env bash
# Builds a standalone Secure Your System app (macOS: dist/Evans-Secure-Your-System.app, Linux: dist/Evans-Secure-Your-System)
cd "$(dirname "$0")" || exit 1
python3 -m venv .build-venv
.build-venv/bin/python -m pip install --upgrade pip
.build-venv/bin/python -m pip install -r requirements.txt pyinstaller
.build-venv/bin/pyinstaller --noconfirm --onefile --windowed --name "Evans-Secure-Your-System" run.py
cp -R custom_iocs dist/
cp README.md dist/
echo "Done. Your program is in the dist folder."
