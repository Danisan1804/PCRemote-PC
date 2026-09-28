@echo off
cd /d "%~dp0"

echo Instalando dependencias...
python -m pip install --quiet fastapi "uvicorn[standard]" mss opencv-python psutil pyautogui pillow numpy python-multipart

echo Registrando arranque automatico...

:: Crear tarea directamente con schtasks sin pasar por el launcher
schtasks /Create /TN "PCRemoteLauncher" /F ^
  /SC ONLOGON ^
  /TR "\"%~dp0iniciar.bat\"" ^
  /RL HIGHEST

echo OK - arrancara solo con Windows.
echo.
echo Iniciando servidor ahora...
start "" /B pythonw "%~dp0pc_remote_launcher.pyw"
pause
