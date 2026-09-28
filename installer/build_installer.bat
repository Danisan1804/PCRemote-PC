@echo off
setlocal
cd /d "%~dp0.."

if not exist "venv\Scripts\python.exe" (
    echo No se encontro el entorno virtual de PC Remote.
    pause
    exit /b 1
)

venv\Scripts\python.exe -m pip install pyinstaller
if errorlevel 1 (
    echo No se pudo preparar PyInstaller.
    pause
    exit /b 1
)
if exist venv.zip del /q venv.zip
powershell -NoProfile -Command "Compress-Archive -Path 'venv\*' -DestinationPath 'venv.zip' -Force"
if errorlevel 1 (
    echo No se pudo crear venv.zip.
    pause
    exit /b 1
)
venv\Scripts\python.exe -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name PCRemoteSetup ^
  --add-data "server.py;payload" ^
  --add-data "pc_remote_launcher.pyw;payload" ^
  --add-data "iniciar.bat;payload" ^
  --add-data "DESINSTALAR.bat;payload" ^
  --add-data "INSTALAR.bat;payload" ^
  --add-data "README.md;payload" ^
  --add-data "remote_files;payload\remote_files" ^
  --add-data "pwa;payload\pwa" ^
  --add-data "venv.zip;payload" ^
  --add-data "installer\TERMINOS.txt;payload\installer" ^
  installer\setup_gui.py
if errorlevel 1 (
    echo PyInstaller no pudo generar el ejecutable.
    pause
    exit /b 1
)

echo.
echo Instalador creado en dist\PCRemoteSetup.exe
pause
