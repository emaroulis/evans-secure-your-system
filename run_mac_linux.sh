#!/usr/bin/env bash
# Starts Secure Your System. First run creates a private Python environment in .venv
cd "$(dirname "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 was not found."
  echo "macOS: install from https://www.python.org/downloads/  |  Linux: sudo apt install python3 python3-venv python3-tk"
  exit 1
fi
if [ ! -x ".venv/bin/python" ]; then
  echo "First run: setting up Secure Your System (about a minute)..."
  python3 -m venv .venv || { echo "Could not create environment. On Linux: sudo apt install python3-venv"; exit 1; }
  .venv/bin/python -m pip install --upgrade pip >/dev/null
  .venv/bin/python -m pip install -r requirements.txt
fi
exec .venv/bin/python -m secure_your_system "$@"
