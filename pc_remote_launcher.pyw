"""
PC Remote Launcher v3
- Apunta a server.py
- Arranque silencioso, sin ventana
- Reinicia el servidor si se cae
- Se registra solo en Task Scheduler
"""
import subprocess, sys, time, socket
from pathlib import Path
from datetime import datetime

SCRIPT_DIR  = Path(__file__).resolve().parent
SERVER_FILE = SCRIPT_DIR / "server.py"
LOG_FILE    = SCRIPT_DIR / "pc_remote.log"
PORT        = 8000
PYTHON      = sys.executable
TASK_NAME   = "PCRemoteLauncher"

def log(msg):
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > 512 * 1024:
            LOG_FILE.write_text("")
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass

def port_free():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("localhost", PORT)) != 0

def start_server():
    return subprocess.Popen(
        [PYTHON, "-m", "uvicorn", "server:app",
         "--host", "0.0.0.0", "--port", str(PORT), "--log-level", "warning"],
        cwd=str(SCRIPT_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
    )

def register_task():
    r = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if r.returncode == 0:
        return
    pythonw = Path(sys.executable).parent / "pythonw.exe"
    if not pythonw.exists():
        pythonw = Path(sys.executable)
    launcher = Path(__file__).resolve()
    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions><Exec>
    <Command>{pythonw}</Command>
    <Arguments>"{launcher}"</Arguments>
    <WorkingDirectory>{launcher.parent}</WorkingDirectory>
  </Exec></Actions>
</Task>"""
    tmp = SCRIPT_DIR / "_task.xml"
    tmp.write_text(xml, encoding="utf-16")
    subprocess.run(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", str(tmp), "/F"],
                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    tmp.unlink(missing_ok=True)
    log("Registrado en Task Scheduler.")

def main():
    log("=== Launcher iniciado ===")
    if not SERVER_FILE.exists():
        log(f"ERROR: {SERVER_FILE} no existe.")
        return
    try:
        register_task()
    except Exception as e:
        log(f"Task Scheduler error: {e}")

    while True:
        if not port_free():
            time.sleep(10)
            continue
        try:
            proc = start_server()
            log(f"Servidor iniciado (PID {proc.pid})")
        except Exception as e:
            log(f"Error al iniciar: {e}")
            time.sleep(10)
            continue
        while True:
            time.sleep(5)
            if proc.poll() is not None:
                log(f"Servidor caído (código {proc.returncode}). Reiniciando...")
                break

if __name__ == "__main__":
    main()
