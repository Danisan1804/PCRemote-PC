from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


APP_NAME = "PC Remote"
PASSWORD_ITERATIONS = 310_000


def source_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS")) / "payload"
    return Path(__file__).resolve().parents[1]


def make_password_record(username: str, password: str) -> dict:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return {
        "username": username,
        "password_hash": digest.hex(),
        "password_scheme": "pbkdf2_sha256",
        "password_salt": salt.hex(),
        "setup_required": False,
    }


def tailscale_check() -> tuple[bool, bool]:
    executable = shutil.which("tailscale")
    if not executable:
        return False, False
    try:
        result = subprocess.run(
            [executable, "ip", "-4"],
            capture_output=True,
            text=True,
            timeout=4,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return True, result.returncode == 0 and bool(result.stdout.strip())
    except Exception:
        return True, False


def install_payload(destination: Path, username: str, password: str) -> Path:
    """Copia una instalación completa sin registrar tareas ni iniciar procesos."""
    destination = destination.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    root = source_root()
    for name in ["server.py", "pc_remote_launcher.pyw", "iniciar.bat", "DESINSTALAR.bat", "INSTALAR.bat", "README.md"]:
        source = root / name
        if source.exists():
            shutil.copy2(source, destination / name)
    if (root / "remote_files").exists():
        shutil.copytree(root / "remote_files", destination / "remote_files", dirs_exist_ok=True)
    if (root / "pwa").exists():
        shutil.copytree(root / "pwa", destination / "pwa", dirs_exist_ok=True)
    bundled_venv = root / "venv.zip"
    if bundled_venv.exists():
        import zipfile
        venv_destination = destination / "venv"
        venv_destination.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(bundled_venv) as archive:
            archive.extractall(venv_destination)
    (destination / "pc_remote_auth.json").write_text(
        json.dumps(make_password_record(username, password), indent=2), encoding="utf-8"
    )
    (destination / "iniciar.bat").write_text(
        '@echo off\ncd /d "%~dp0"\n'
        'if exist "%~dp0venv\\Scripts\\pythonw.exe" '
        'start "" /B "%~dp0venv\\Scripts\\pythonw.exe" "%~dp0pc_remote_launcher.pyw"\n'
        'if not exist "%~dp0venv\\Scripts\\pythonw.exe" '
        'start "" /B pythonw "%~dp0pc_remote_launcher.pyw"\n',
        encoding="utf-8",
    )
    return destination


def register_startup(destination: Path) -> None:
    subprocess.run(
        ["schtasks", "/Create", "/TN", "PCRemoteLauncher", "/F", "/SC", "ONLOGON", "/TR", f'"{destination / "iniciar.bat"}"', "/RL", "LIMITED"],
        capture_output=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def launch_installation(destination: Path) -> None:
    subprocess.Popen(
        ["cmd", "/c", str(destination / "iniciar.bat")],
        cwd=str(destination),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


class Installer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PC Remote — Instalación")
        self.geometry("700x560")
        self.minsize(620, 480)
        self.resizable(True, True)
        self.destination = tk.StringVar(
            value=str(Path(os.environ.get("LOCALAPPDATA", Path.home())) / "PCRemote")
        )
        self.username = tk.StringVar(value="admin")
        self.password = tk.StringVar()
        self.password_confirmation = tk.StringVar()
        self.accepted = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="")
        self._build()

    def _build(self):
        outer = ttk.Frame(self, padding=18)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="PC Remote", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(
            outer,
            text="Instalación del servidor remoto para Windows",
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(0, 14))

        terms_frame = ttk.LabelFrame(outer, text="Términos y seguridad", padding=10)
        terms_frame.pack(fill="both", expand=True)
        terms = tk.Text(terms_frame, wrap="word", height=16, state="normal")
        terms.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(terms_frame, command=terms.yview)
        scroll.pack(side="right", fill="y")
        terms.configure(yscrollcommand=scroll.set)
        terms_path = Path(__file__).with_name("TERMINOS.txt")
        if not terms_path.exists():
            terms_path = source_root() / "installer" / "TERMINOS.txt"
        terms.insert("1.0", terms_path.read_text(encoding="utf-8") if terms_path.exists() else "No se encontró el texto de términos.")
        terms.configure(state="disabled")
        ttk.Checkbutton(
            outer,
            text="He leído y acepto los términos y el aviso de seguridad.",
            variable=self.accepted,
        ).pack(anchor="w", pady=10)

        form = ttk.LabelFrame(outer, text="Configuración de esta instalación", padding=10)
        form.pack(fill="x")
        ttk.Label(form, text="Carpeta de instalación:").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.destination).grid(row=0, column=1, sticky="ew", padx=8, pady=4)
        ttk.Button(form, text="Examinar", command=self.choose_destination).grid(row=0, column=2, pady=4)
        ttk.Label(form, text="Usuario local:").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.username).grid(row=1, column=1, columnspan=2, sticky="ew", padx=8, pady=4)
        ttk.Label(form, text="Contraseña de PC Remote:").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.password, show="•").grid(row=2, column=1, columnspan=2, sticky="ew", padx=8, pady=4)
        ttk.Label(form, text="Repetir contraseña:").grid(row=3, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.password_confirmation, show="•").grid(row=3, column=1, columnspan=2, sticky="ew", padx=8, pady=4)
        form.columnconfigure(1, weight=1)

        self.tailscale_label = ttk.Label(form, text="Comprobando Tailscale...")
        self.tailscale_label.grid(row=4, column=0, columnspan=3, sticky="w", pady=(8, 0))
        threading.Thread(target=self.check_tailscale, daemon=True).start()

        ttk.Label(outer, textvariable=self.status, foreground="#555").pack(anchor="w", pady=(10, 0))
        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, text="Cancelar", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="Instalar", command=self.install).pack(side="right", padx=8)

    def choose_destination(self):
        selected = filedialog.askdirectory(title="Elegir carpeta de instalación")
        if selected:
            self.destination.set(selected)

    def check_tailscale(self):
        installed, connected = tailscale_check()
        text = (
            "Tailscale: instalado y conectado."
            if installed and connected
            else "Tailscale: instalado, pero no aparece conectado."
            if installed
            else "Tailscale: no se encontró. Se puede instalar después."
        )
        self.after(0, lambda: self.tailscale_label.configure(text=text))

    def install(self):
        if not self.accepted.get():
            messagebox.showwarning(APP_NAME, "Debes aceptar los términos para continuar.")
            return
        username = self.username.get().strip()
        password = self.password.get()
        if not username or len(password) < 10:
            messagebox.showwarning(APP_NAME, "Usa un usuario y una contraseña de al menos 10 caracteres.")
            return
        if password != self.password_confirmation.get():
            messagebox.showwarning(APP_NAME, "Las contraseñas no coinciden.")
            return
        try:
            destination = Path(self.destination.get()).expanduser().resolve()
            install_payload(destination, username, password)
            self.status.set("Archivos copiados. Configurando el arranque...")
            register_startup(destination)
            launch_installation(destination)
            messagebox.showinfo(APP_NAME, f"PC Remote quedó instalado en:\n{destination}\n\nGuarda la contraseña local que acabas de crear.")
            self.destroy()
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"No se pudo completar la instalación:\n{exc}")


if __name__ == "__main__":
    Installer().mainloop()
