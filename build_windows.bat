@echo off
REM Builds a single Evans-Secure-Your-System.exe that runs without Python installed.
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py -3) || (set PY=python)
%PY% -m venv .build-venv
".build-venv\Scripts\python.exe" -m pip install --upgrade pip
".build-venv\Scripts\python.exe" -m pip install -r requirements.txt pyinstaller
".build-venv\Scripts\pyinstaller.exe" --noconfirm --onefile --windowed --name "Evans-Secure-Your-System" run.py
xcopy /E /I /Y custom_iocs dist\custom_iocs >nul
copy /Y README.md dist\ >nul
echo.
echo Done. Your program is in the "dist" folder: dist\Evans-Secure-Your-System.exe
pause
