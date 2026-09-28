from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.responses import (
    HTMLResponse,
    StreamingResponse,
    FileResponse,
    Response,
    JSONResponse
)
from fastapi.middleware.cors import CORSMiddleware
import mss
import cv2
import psutil
import pyautogui
from PIL import Image
import io
import time
import asyncio
import subprocess
import platform
import os
from pathlib import Path
import shutil
import urllib.parse
import secrets
import hashlib
import json
import urllib.request
import urllib.error
import datetime


app = FastAPI(title="PC Remote")

_pwa_origins = [
    origin.strip()
    for origin in os.getenv("PCREMOTE_PWA_ORIGINS", "").split(",")
    if origin.strip()
]
if _pwa_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_pwa_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization"],
    )

LOCAL_ASSISTANT_MODEL = os.getenv("PCREMOTE_LOCAL_MODEL", "qwen3.5:0.8b")
OLLAMA_URL = os.getenv("PCREMOTE_OLLAMA_URL", "http://localhost:11434/api/generate")


# ==========================================================
# CONFIGURACIÓN
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent

REMOTE_ROOT = BASE_DIR / "remote_files"
INSTANCE_CONFIG_FILE = BASE_DIR / "pc_remote_instance.json"

REMOTE_ROOT.mkdir(
    exist_ok=True
)

# ==========================================================
# SEGURIDAD DE RUTAS
# ==========================================================

def safe_path(relative_path: str = "") -> Path:
    relative_path = relative_path.replace("\\", "/")
    relative_path = relative_path.strip("/")
    requested = (REMOTE_ROOT / relative_path).resolve()
    root = REMOTE_ROOT.resolve()
    try:
        requested.relative_to(root)
    except ValueError:
        raise HTTPException(status_code=403, detail="Ruta no permitida")
    return requested


# ==========================================================
# AUTENTICACIÓN

# ==========================================================
# CHANGE_PASSWORD_MODULE_V1
# CREDENCIALES PERSISTENTES
# ==========================================================

AUTH_CONFIG_FILE = Path(__file__).with_name("pc_remote_auth.json")


def load_instance_config():
    default = {
        "installation_id": secrets.token_urlsafe(18),
        "display_name": platform.node() or "Mi PC",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
    try:
        if INSTANCE_CONFIG_FILE.exists():
            data = json.loads(INSTANCE_CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("installation_id"):
                return {**default, **data}
    except Exception:
        pass
    try:
        INSTANCE_CONFIG_FILE.write_text(json.dumps(default, indent=2), encoding="utf-8")
    except Exception:
        pass
    return default


INSTANCE_CONFIG = load_instance_config()


def load_auth_config():
    default = {
        "username": "admin",
        "password_hash": "",
        "password_scheme": "pbkdf2_sha256",
        "password_salt": "",
        "setup_required": True
    }

    try:
        if AUTH_CONFIG_FILE.exists():
            data = json.loads(
                AUTH_CONFIG_FILE.read_text(encoding="utf-8")
            )

            if (
                isinstance(data, dict)
                and isinstance(data.get("username"), str)
                and isinstance(data.get("password_hash"), str)
                and data["username"]
                and data["password_hash"]
            ):
                return data
    except Exception:
        pass

    try:
        AUTH_CONFIG_FILE.write_text(
            json.dumps(default, indent=2),
            encoding="utf-8"
        )
    except Exception:
        pass

    return default


AUTH_CONFIG = load_auth_config()
AUTH_USERNAME = AUTH_CONFIG["username"]
PASSWORD_HASH = AUTH_CONFIG["password_hash"]
PASSWORD_SCHEME = AUTH_CONFIG.get("password_scheme", "legacy_sha256")
PASSWORD_SALT = AUTH_CONFIG.get("password_salt", "")
SETUP_REQUIRED = bool(AUTH_CONFIG.get("setup_required", not PASSWORD_HASH))


def save_auth_config(username: str, password: str):
    global AUTH_CONFIG, AUTH_USERNAME, PASSWORD_HASH
    global PASSWORD_SCHEME, PASSWORD_SALT, SETUP_REQUIRED

    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 310_000
    )

    new_config = {
        "username": username,
        "password_hash": password_hash.hex(),
        "password_scheme": "pbkdf2_sha256",
        "password_salt": salt.hex(),
        "setup_required": False
    }

    AUTH_CONFIG_FILE.write_text(
        json.dumps(new_config, indent=2),
        encoding="utf-8"
    )

    AUTH_CONFIG = new_config
    AUTH_USERNAME = username
    PASSWORD_HASH = new_config["password_hash"]
    PASSWORD_SCHEME = new_config["password_scheme"]
    PASSWORD_SALT = new_config["password_salt"]
    SETUP_REQUIRED = False


def verify_password(password: str) -> bool:
    if SETUP_REQUIRED or not PASSWORD_HASH:
        return False
    if PASSWORD_SCHEME == "pbkdf2_sha256" and PASSWORD_SALT:
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(PASSWORD_SALT), 310_000
        ).hex()
    else:
        candidate = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return secrets.compare_digest(candidate, PASSWORD_HASH)


# ==========================================================

# Las credenciales se cargan desde pc_remote_auth.json.

SESSION_TTL_SECONDS = 12 * 60 * 60
SESSIONS = {}
LOGIN_FAILURES = {}
MAX_LOGIN_ATTEMPTS = 8
LOGIN_WINDOW_SECONDS = 15 * 60


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def create_session():
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = time.time() + SESSION_TTL_SECONDS
    return token


def valid_session(request: Request):
    token = request.cookies.get("pc_remote_session")
    if not token:
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
    if not token:
        return False
    expires_at = SESSIONS.get(token)
    if not expires_at:
        return False
    if expires_at <= time.time():
        SESSIONS.pop(token, None)
        return False
    return True



def require_session(request: Request):
    if not valid_session(request):
        raise HTTPException(
            status_code=401,
            detail="No autenticado"
        )



# ==========================================================
# CAMBIAR CONTRASEÑA
# ==========================================================

@app.post("/change-password")
async def change_password(request: Request):
    require_session(request)

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Solicitud inválida.")

    current_password = str(data.get("current_password", ""))
    new_password = str(data.get("new_password", ""))
    confirm_password = str(data.get("confirm_password", ""))

    if not verify_password(current_password):
        raise HTTPException(
            status_code=400,
            detail="La contraseña actual es incorrecta."
        )

    if len(new_password) < 8:
        raise HTTPException(
            status_code=400,
            detail="La nueva contraseña debe tener al menos 8 caracteres."
        )

    if new_password != confirm_password:
        raise HTTPException(
            status_code=400,
            detail="Las contraseñas nuevas no coinciden."
        )

    if new_password == current_password:
        raise HTTPException(
            status_code=400,
            detail="La nueva contraseña debe ser diferente."
        )

    save_auth_config(AUTH_USERNAME, new_password)

    return {
        "success": True,
        "message": "Contraseña cambiada correctamente."
    }


# ==========================================================
# LOGIN
# ==========================================================

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PC Remote - Acceso</title>
<style>
* { box-sizing: border-box; }
body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #111;
    color: white;
    font-family: Arial, sans-serif;
}
.login {
    width: 92%;
    max-width: 380px;
    background: #1b1b1b;
    border: 1px solid #444;
    border-radius: 16px;
    padding: 25px;
    text-align: center;
}
.login h1 { margin-top: 0; }
.login input {
    width: 100%;
    padding: 13px;
    margin: 7px 0;
    border-radius: 8px;
    border: 1px solid #555;
    background: #222;
    color: white;
    font-size: 16px;
}
.login button {
    width: 100%;
    padding: 13px;
    margin-top: 10px;
    border-radius: 8px;
    border: 1px solid #555;
    background: #292929;
    color: white;
    font-size: 16px;
}
#error { color: #f87171; min-height: 22px; margin-top: 10px; }
</style>
</head>
<body>
<div class="login">
    <h1>🔐 PC Remote</h1>
    <p>Inicia sesión para controlar tu PC.</p>
    <input id="username" type="text" placeholder="Usuario" autocomplete="username">
    <input id="password" type="password" placeholder="Contraseña" autocomplete="current-password">
    <button onclick="login()">Entrar</button>
    <div id="error"></div>
</div>
<script>
async function login() {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const error = document.getElementById("error");
    error.innerText = "";
    try {
        const response = await fetch("/login", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({username, password})
        });
        const data = await response.json();
        if (!response.ok || !data.success) {
            error.innerText = data.error || "Usuario o contraseña incorrectos.";
            return;
        }
        window.location.href = "/";
    } catch (e) {
        error.innerText = "No se pudo conectar con el servidor.";
    }
}
document.getElementById("password").addEventListener("keydown", function(e) {
    if (e.key === "Enter") login();
});


async function logout() {
    try {
        await fetch("/logout", {method: "POST"});
    } finally {
        window.location.href = "/login";
    }
}
</script>
</body>
</html>
"""

@app.middleware("http")
async def authentication_middleware(request: Request, call_next):
    public_paths = {"/login", "/favicon.ico", "/api/instance/status"}
    is_pwa_asset = request.url.path == "/pwa" or request.url.path.startswith("/pwa/")

    if request.url.path not in public_paths and not is_pwa_asset and not valid_session(request):
        if request.url.path == "/":
            return HTMLResponse(
                '<script>window.location.href="/login";</script>',
                status_code=401
            )
        return HTMLResponse("No autenticado", status_code=401)

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if valid_session(request):
        return HTMLResponse('<script>window.location.href="/";</script>')
    return LOGIN_HTML


@app.post("/login")
async def login(request: Request):
    data = await request.json()
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))

    client_key = _client_key(request)
    now = time.time()
    failures = [t for t in LOGIN_FAILURES.get(client_key, [])
                if now - t < LOGIN_WINDOW_SECONDS]
    if len(failures) >= MAX_LOGIN_ATTEMPTS:
        return HTMLResponse(
            '{"success":false,"error":"Demasiados intentos. Intenta más tarde."}',
            status_code=429,
            media_type="application/json"
        )

    if (secrets.compare_digest(username, AUTH_USERNAME) and verify_password(password)):
        LOGIN_FAILURES.pop(client_key, None)
        token = create_session()
        response = JSONResponse({
            "success": True,
            "token": token,
            "instance": {
                "id": INSTANCE_CONFIG.get("installation_id"),
                "name": INSTANCE_CONFIG.get("display_name") or platform.node() or "Mi PC"
            }
        })
        response.set_cookie(
            "pc_remote_session",
            token,
            httponly=True,
            samesite="strict",
            secure=os.getenv("PCREMOTE_HTTPS", "0") == "1",
            max_age=SESSION_TTL_SECONDS
        )
        return response

    failures.append(now)
    LOGIN_FAILURES[client_key] = failures

    return HTMLResponse(
        '{"success":false,"error":"Usuario o contraseña incorrectos."}',
        status_code=401,
        media_type="application/json"
    )


@app.post("/logout")
async def logout(request: Request):
    token = request.cookies.get("pc_remote_session")
    if not token:
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
    if token:
        SESSIONS.pop(token, None)
    response = HTMLResponse('{"success":true}', media_type="application/json")
    response.delete_cookie("pc_remote_session")
    return response


def tailscale_status():
    executable = shutil.which("tailscale")
    if not executable:
        return {"installed": False, "connected": False}
    try:
        result = subprocess.run(
            [executable, "ip", "-4"],
            capture_output=True,
            text=True,
            timeout=3,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
        addresses = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return {"installed": True, "connected": result.returncode == 0 and bool(addresses)}
    except Exception:
        return {"installed": True, "connected": False}


@app.get("/api/instance/status")
def instance_status():
    """Estado mínimo para que una PWA pueda comprobar esta instalación."""
    return {
        "configured": not SETUP_REQUIRED,
        "display_name": INSTANCE_CONFIG.get("display_name") or platform.node() or "Mi PC",
        "server": "online",
        "tailscale": tailscale_status()
    }


PWA_ROOT = BASE_DIR / "pwa"
PWA_ASSETS = {
    "control.html": "text/html; charset=utf-8",
    "control.js": "text/javascript; charset=utf-8",
    "control.css": "text/css; charset=utf-8",
    "manifest.webmanifest": "application/manifest+json",
    "app.js": "text/javascript; charset=utf-8",
    "styles.css": "text/css; charset=utf-8",
    "sw.js": "text/javascript; charset=utf-8",
    "icon.svg": "image/svg+xml",
}


@app.get("/pwa", response_class=HTMLResponse)
@app.get("/pwa/", response_class=HTMLResponse)
def pwa_index():
    index = PWA_ROOT / "index.html"
    if not index.exists():
        raise HTTPException(status_code=404, detail="PWA no instalada")
    return FileResponse(index, media_type="text/html; charset=utf-8")


@app.get("/pwa/{asset_name}")
def pwa_asset(asset_name: str):
    media_type = PWA_ASSETS.get(asset_name)
    if not media_type:
        raise HTTPException(status_code=404, detail="Recurso no encontrado")
    asset = PWA_ROOT / asset_name
    if not asset.exists():
        raise HTTPException(status_code=404, detail="Recurso no encontrado")
    return FileResponse(asset, media_type=media_type)


# ==========================================================
# ASISTENTE LOCAL SIN API DE PAGO
# ==========================================================

LOCAL_ASSISTANT_SYSTEM = """Eres el asistente local de PCRemote. Responde SOLO con JSON válido,
sin markdown, usando exactamente este formato:
{"action":"none|lock|restart|shutdown|cancel","reply":"respuesta breve"}
Solo puedes seleccionar lock, restart, shutdown o cancel cuando el usuario lo pida
claramente. Para cualquier otra petición usa none. No inventes acciones ni ejecutes
comandos del sistema. Responde en español."""


def _simple_local_intent(text: str):
    normalized = " ".join(text.lower().strip().split())
    if any(word in normalized for word in ("bloquea", "bloquear", "bloqueo")):
        return {"action": "lock", "reply": "Voy a bloquear el PC."}
    if any(word in normalized for word in ("cancela apagado", "cancelar apagado", "cancela reinicio")):
        return {"action": "cancel", "reply": "Voy a cancelar la acción de energía."}
    if any(word in normalized for word in ("reinicia", "reiniciar", "reinicio")):
        return {"action": "restart", "reply": "Se solicitó reiniciar el PC."}
    if any(word in normalized for word in ("apaga", "apagar", "apagado")):
        return {"action": "shutdown", "reply": "Se solicitó apagar el PC."}
    return {"action": "none", "reply": "No reconocí una acción autorizada."}


def _ollama_intent(text: str):
    payload = json.dumps({
        "model": LOCAL_ASSISTANT_MODEL,
        "system": LOCAL_ASSISTANT_SYSTEM,
        "prompt": text,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0}
    }).encode("utf-8")
    request = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.loads(response.read().decode("utf-8"))
    raw_result = body.get("response") or body.get("thinking") or "{}"
    raw_result = str(raw_result).strip()
    if raw_result.startswith("```"):
        raw_result = raw_result.replace("```json", "", 1).replace("```", "", 1).strip()
    result = json.loads(raw_result)
    action = result.get("action")
    if action not in {"none", "lock", "restart", "shutdown", "cancel"}:
        raise ValueError("Acción local no válida")
    return {"action": action, "reply": str(result.get("reply", ""))[:300]}


@app.post("/api/local-assistant/command")
async def local_assistant_command(request: Request):
    require_session(request)
    try:
        data = await request.json()
        text = str(data.get("text", "")).strip()
    except Exception:
        raise HTTPException(status_code=400, detail="Solicitud inválida.")
    if not text or len(text) > 500:
        raise HTTPException(status_code=400, detail="El comando debe tener entre 1 y 500 caracteres.")

    try:
        result = await asyncio.to_thread(_ollama_intent, text)
        result["source"] = "ollama"
    except Exception:
        result = _simple_local_intent(text)
        result["source"] = "fallback"
    return result


# ==========================================================
# HTML
# ==========================================================

HTML = """

<!DOCTYPE html>

<html>

<head>

<meta name="viewport"
content="width=device-width, initial-scale=1.0,
maximum-scale=1.0, user-scalable=no">

<title>PC Remote</title>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    background: #111;

    color: white;

    font-family: Arial, sans-serif;

    text-align: center;
}


h1 {

    margin: 12px 0 5px;

    font-size: 23px;
}


.status {

    color: #4ade80;

    margin-bottom: 12px;
}


.screen-container {

    width: 100%;

    padding: 5px;
}


#screen {

    display: block;

    width: 100%;

    max-width: 1400px;

    height: auto;

    margin: auto;

    border: 2px solid #444;

    border-radius: 8px;

    touch-action: none;

    user-select: none;

    -webkit-user-select: none;
}


.controls {

    margin: 12px auto;

    display: flex;

    justify-content: center;

    gap: 8px;

    flex-wrap: wrap;
}


button {

    background: #292929;

    color: white;

    border: 1px solid #555;

    border-radius: 9px;

    padding: 11px 15px;

    font-size: 15px;
}


button:active {

    background: #555;
}


#coordinates {

    color: #aaa;

    font-size: 12px;

    margin: 8px;
}



/* =====================================================
   CÁMARA
===================================================== */

.camera {
    width: 95%;
    max-width: 1000px;
    margin: 25px auto;
    padding: 15px;
    background: #1b1b1b;
    border: 1px solid #444;
    border-radius: 12px;
}

#cameraView {
    display: block;
    width: 100%;
    max-width: 900px;
    margin: 10px auto;
    border: 2px solid #444;
    border-radius: 8px;
    background: #000;
}

.camera-status {
    color: #aaa;
    margin: 8px;
}

/* =====================================================
   TECLADO
===================================================== */

.keyboard {
    width: min(100%, 1000px);
    margin: 15px auto;
    padding: 10px 6px;
    overflow-x: auto;
    background: #171717;
    border: 1px solid #333;
    border-radius: 12px;
}


.keyboard-row {
    display: flex;
    justify-content: center;
    gap: 5px;
    margin-bottom: 6px;
    flex-wrap: nowrap;
    min-width: 520px;
}


.key {
    flex: 1 1 0;
    min-width: 0;
    height: 44px;
    padding: 4px 3px;
    background: #252525;
    border: 1px solid #555;
    border-radius: 7px;
    color: white;
    font-size: clamp(11px, 2.2vw, 14px);
    display: flex;
    align-items: center;
    justify-content: center;
    touch-action: manipulation;
    white-space: nowrap;
}


.key:active {

    background: #666;
}


.wide {
    flex-grow: 1.55;
}


.space {
    flex-grow: 3;
}

@media (max-width: 600px) {
    .keyboard { margin: 10px 0; padding: 8px 4px; border-radius: 10px; }
    .keyboard-row { gap: 3px; min-width: 0; }
    .key { height: 40px; border-radius: 6px; font-size: 11px; }
}


.keyboard-input {

    width: 95%;

    max-width: 700px;

    padding: 12px;

    background: #222;

    color: white;

    border: 1px solid #555;

    border-radius: 8px;

    font-size: 16px;

    margin-bottom: 10px;
}


/* =====================================================
   ARCHIVOS
===================================================== */

.files {

    width: 95%;

    max-width: 900px;

    margin: 25px auto;

    background: #1b1b1b;

    border: 1px solid #444;

    border-radius: 12px;

    padding: 15px;

}


.files h2 {

    margin-top: 0;

}


.path {

    background: #111;

    border: 1px solid #444;

    padding: 10px;

    border-radius: 8px;

    margin-bottom: 10px;

    word-break: break-all;

    color: #aaa;
}


.file-list {

    text-align: left;

    margin-top: 10px;
}


.file-item {

    display: flex;

    align-items: center;

    justify-content: space-between;

    gap: 10px;

    padding: 10px;

    border-bottom: 1px solid #333;
}


.file-name {

    flex: 1;

    overflow: hidden;

    text-overflow: ellipsis;

}


.file-actions {

    display: flex;

    gap: 5px;

}


.file-actions button {

    padding: 7px 9px;

    font-size: 13px;
}


.folder {

    color: #60a5fa;

}


.file {

    color: #ddd;

}


.upload {

    margin-top: 15px;

    padding: 15px;

    border-top: 1px solid #333;
}


input[type="file"] {

    max-width: 100%;

    color: white;

}


</style>

</head>


<body>


<h1>🖥️ PC Remote</h1>


<div class="status">

● PC conectado

</div>

<div class="controls">

<button onclick="logout()">

🔒 Cerrar sesión

</button>

</div>


<!-- =====================================================
     PANTALLA
===================================================== -->

<div class="screen-container">

<img
id="screen"
src=""
draggable="false"
fetchpriority="high"
decoding="async"
>

</div>


<div class="controls">

<button onclick="mouseClick('left')">

🖱️ Clic izquierdo

</button>


<button onclick="mouseClick('right')">

🖱️ Clic derecho

</button>

</div>


<div id="coordinates">

Mouse: esperando...

</div>


<!-- =====================================================
     TECLADO
===================================================== -->

<input
id="textInput"
class="keyboard-input"
type="text"
placeholder="Escribe aquí..."
autocomplete="off"
>


<div class="controls">

<button onclick="sendText()">

⌨️ Enviar texto

</button>


<button onclick="sendKey('enter')">

↵ Enter

</button>


<button onclick="sendKey('backspace')">

⌫ Borrar

</button>

</div>


<div class="keyboard">


<div class="keyboard-row">

<button class="key"
onclick="sendKey('escape')">

ESC

</button>


<button class="key"
onclick="sendKey('f1')">

F1

</button>


<button class="key"
onclick="sendKey('f2')">

F2

</button>


<button class="key"
onclick="sendKey('f3')">

F3

</button>


<button class="key"
onclick="sendKey('f4')">

F4

</button>


<button class="key"
onclick="sendKey('f5')">

F5

</button>


<button class="key"
onclick="sendKey('f6')">

F6

</button>


<button class="key"
onclick="sendKey('f7')">

F7

</button>


<button class="key"
onclick="sendKey('f8')">

F8

</button>


<button class="key"
onclick="sendKey('f9')">

F9

</button>


<button class="key"
onclick="sendKey('f10')">

F10

</button>


<button class="key"
onclick="sendKey('f11')">

F11

</button>


<button class="key"
onclick="sendKey('f12')">

F12

</button>

</div>


<div class="keyboard-row">

<button class="key"
onclick="sendKey('1')">1</button>

<button class="key"
onclick="sendKey('2')">2</button>

<button class="key"
onclick="sendKey('3')">3</button>

<button class="key"
onclick="sendKey('4')">4</button>

<button class="key"
onclick="sendKey('5')">5</button>

<button class="key"
onclick="sendKey('6')">6</button>

<button class="key"
onclick="sendKey('7')">7</button>

<button class="key"
onclick="sendKey('8')">8</button>

<button class="key"
onclick="sendKey('9')">9</button>

<button class="key"
onclick="sendKey('0')">0</button>

</div>


<div class="keyboard-row">

<button class="key wide"
onclick="sendKey('tab')">

TAB

</button>


<button class="key"
onclick="sendKey('q')">Q</button>

<button class="key"
onclick="sendKey('w')">W</button>

<button class="key"
onclick="sendKey('e')">E</button>

<button class="key"
onclick="sendKey('r')">R</button>

<button class="key"
onclick="sendKey('t')">T</button>

<button class="key"
onclick="sendKey('y')">Y</button>

<button class="key"
onclick="sendKey('u')">U</button>

<button class="key"
onclick="sendKey('i')">I</button>

<button class="key"
onclick="sendKey('o')">O</button>

<button class="key"
onclick="sendKey('p')">P</button>

</div>


<div class="keyboard-row">

<button class="key wide"
onclick="sendKey('capslock')">

CAPS

</button>


<button class="key"
onclick="sendKey('a')">A</button>

<button class="key"
onclick="sendKey('s')">S</button>

<button class="key"
onclick="sendKey('d')">D</button>

<button class="key"
onclick="sendKey('f')">F</button>

<button class="key"
onclick="sendKey('g')">G</button>

<button class="key"
onclick="sendKey('h')">H</button>

<button class="key"
onclick="sendKey('j')">J</button>

<button class="key"
onclick="sendKey('k')">K</button>

<button class="key"
onclick="sendKey('l')">L</button>

</div>


<div class="keyboard-row">

<button class="key wide"
onclick="sendKey('shift')">

SHIFT

</button>


<button class="key"
onclick="sendKey('z')">Z</button>

<button class="key"
onclick="sendKey('x')">X</button>

<button class="key"
onclick="sendKey('c')">C</button>

<button class="key"
onclick="sendKey('v')">V</button>

<button class="key"
onclick="sendKey('b')">B</button>

<button class="key"
onclick="sendKey('n')">N</button>

<button class="key"
onclick="sendKey('m')">M</button>

</div>


<div class="keyboard-row">

<button class="key wide"
onclick="sendKey('ctrl')">

CTRL

</button>


<button class="key wide"
onclick="sendKey('alt')">

ALT

</button>


<button class="key space"
onclick="sendKey('space')">

ESPACIO

</button>


<button class="key wide"
onclick="sendKey('win')">

WIN

</button>

</div>


<div class="keyboard-row">

<button class="key"
onclick="sendKey('left')">

←

</button>


<button class="key"
onclick="sendKey('up')">

↑

</button>


<button class="key"
onclick="sendKey('down')">

↓

</button>


<button class="key"
onclick="sendKey('right')">

→

</button>

</div>


</div>



<!-- =====================================================
     CÁMARA
===================================================== -->

<section class="local-assistant">
    <h2>🎙️ Asistente local</h2>
    <p class="local-assistant-help">Procesa comandos en este PC con Ollama. No usa API de pago.</p>
    <div class="local-assistant-row">
        <input id="localAssistantText" type="text" maxlength="500"
               placeholder="Ej.: bloquear el PC" autocomplete="off">
        <button type="button" onclick="startLocalVoice()">🎤 Hablar</button>
        <button type="button" onclick="sendLocalCommand()">▶ Ejecutar</button>
    </div>
    <div id="localAssistantStatus" class="local-assistant-status">Listo.</div>
</section>
<style>
.local-assistant{width:95%;max-width:1000px;margin:25px auto;padding:15px;background:#1b1b1b;border:1px solid #444;border-radius:12px;text-align:left}
.local-assistant h2{margin-top:0}
.local-assistant-help{color:#aaa;font-size:13px}
.local-assistant-row{display:flex;gap:8px;flex-wrap:wrap}
.local-assistant-row input{flex:1;min-width:220px;padding:11px;border-radius:9px;border:1px solid #555;background:#222;color:#fff;font-size:15px}
.local-assistant-status{min-height:22px;margin-top:10px;color:#aaa}
</style>

<div class="camera">

    <h2>📷 Cámara del PC</h2>

    <div id="cameraStatus" class="camera-status">
        Cámara apagada
    </div>

    <img id="cameraView" alt="Cámara">

    <div class="controls">

        <button onclick="startCamera()">
            📷 Encender cámara
        </button>

        <button onclick="stopCamera()">
            ⛔ Apagar cámara
        </button>

    </div>

</div>

<!-- =====================================================
     EXPLORADOR DE ARCHIVOS
===================================================== -->

<div class="files">
<h2>💽 Archivos del PC</h2>
<div id="pcFilesPath" class="path">Cargando...</div>
<div class="controls">
    <button onclick="pcFilesGoUp()">⬅️ Atrás</button>
    <button onclick="pcFilesLoad(pcFilesCurrentPath)">🔄 Actualizar</button>
</div>
<div id="pcFilesList" class="file-list">Cargando...</div>
<div class="upload">
    <h3>⬆️ Subir archivo al PC</h3>
    <input type="file" id="pcUploadFile">
    <br><br>
    <button onclick="pcFilesUpload()">⬆️ Subir</button>
</div>
</div>


<script>


// =====================================================
// MOUSE
// =====================================================

const screen =
document.getElementById("screen");


const coordinates =
document.getElementById(
    "coordinates"
);


let lastMove = 0;


function getCoordinates(event) {

    const rect =
        screen.getBoundingClientRect();


    let x;
    let y;


    if (
        event.touches &&
        event.touches.length > 0
    ) {

        x =
            event.touches[0].clientX
            - rect.left;


        y =
            event.touches[0].clientY
            - rect.top;

    } else {

        x =
            event.clientX
            - rect.left;


        y =
            event.clientY
            - rect.top;
    }


    x = Math.max(
        0,
        Math.min(
            x,
            rect.width
        )
    );


    y = Math.max(
        0,
        Math.min(
            y,
            rect.height
        )
    );


    return {

        x: x,

        y: y,

        width: rect.width,

        height: rect.height

    };

}


async function moveMouse(event) {

    event.preventDefault();


    const now = Date.now();


    if (
        now - lastMove < 40
    ) {

        return;

    }


    lastMove = now;


    const position =
        getCoordinates(event);


    coordinates.innerText =
        "Mouse: " +
        Math.round(position.x) +
        " × " +
        Math.round(position.y);


    try {

        await fetch(
            "/mouse/move",
            {

                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify(
                        position
                    )

            }
        );

    } catch (error) {

        console.error(error);

    }

}


async function mouseClick(button) {

    try {

        await fetch(
            "/mouse/click",
            {

                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify({
                        button: button
                    })

            }
        );

    } catch (error) {

        console.error(error);

    }

}


screen.addEventListener(
    "touchstart",
    moveMouse,
    { passive: false }
);


screen.addEventListener(
    "touchmove",
    moveMouse,
    { passive: false }
);


// =====================================================
// TECLADO
// =====================================================

async function sendKey(key) {

    try {

        await fetch(
            "/keyboard/key",
            {

                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify({
                        key: key
                    })

            }
        );

    } catch (error) {

        console.error(error);

    }

}


async function sendText() {

    const input =
        document.getElementById(
            "textInput"
        );


    const text =
        input.value;


    if (!text) {

        return;

    }


    try {

        await fetch(
            "/keyboard/text",
            {

                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify({
                        text: text
                    })

            }
        );


        input.value = "";


    } catch (error) {

        console.error(error);

    }

}



// =====================================================
// PANTALLA — polling de frames individuales (máximos FPS)
// =====================================================

(function initScreen() {
    const img = document.getElementById("screen");
    let running = true;
    let errorDelay = 300; // ms de espera tras error, se resetea en éxito

    async function loop() {
        while (running) {
            try {
                // Fetch directo: cada petición = 1 frame fresco
                const res = await fetch("/frame", { cache: "no-store" });
                if (!res.ok) throw new Error("http " + res.status);
                const blob = await res.blob();
                const url  = URL.createObjectURL(blob);
                const old  = img.src;
                img.src    = url;
                // Liberar URL anterior para no acumular memoria
                if (old && old.startsWith("blob:")) URL.revokeObjectURL(old);
                errorDelay = 300; // resetear delay tras frame exitoso
            } catch (e) {
                // Error de red → esperar un poco antes de reintentar
                await new Promise(r => setTimeout(r, errorDelay));
                errorDelay = Math.min(errorDelay * 2, 3000);
            }
            // Sin await adicional → siguiente frame inmediatamente
            // (la velocidad la limita la red y el servidor)
        }
    }

    loop();
})();

// =====================================================
// CÁMARA
// =====================================================

let cameraRunning = false;

let cameraWatchdog = null;
let cameraLastFrame = 0;

function startCamera() {
    const view = document.getElementById("cameraView");
    const status = document.getElementById("cameraStatus");
    cameraRunning = true;
    cameraLastFrame = Date.now();
    view.src = "/camera?" + Date.now();
    status.innerText = "● Cámara encendida";
    status.style.color = "#4ade80";

    view.onload = () => { cameraLastFrame = Date.now(); };
    view.onerror = () => { if (cameraRunning) setTimeout(() => { view.src = "/camera?" + Date.now(); }, 1500); };

    if (cameraWatchdog) clearInterval(cameraWatchdog);
    cameraWatchdog = setInterval(() => {
        if (cameraRunning && Date.now() - cameraLastFrame > 4000) {
            view.src = "/camera?" + Date.now();
            cameraLastFrame = Date.now();
        }
    }, 2000);
}

function stopCamera() {
    const view = document.getElementById("cameraView");
    const status = document.getElementById("cameraStatus");
    if (cameraWatchdog) { clearInterval(cameraWatchdog); cameraWatchdog = null; }
    view.src = "";
    view.onload = null;
    view.onerror = null;
    cameraRunning = false;
    status.innerText = "Cámara apagada";
    status.style.color = "#aaa";
}

// =====================================================
// ARCHIVOS
// =====================================================

let currentPath = "";


async function loadFiles(path = "") {

    try {

        const response =
            await fetch(
                "/files?path=" +
                encodeURIComponent(path)
            );


        if (!response.ok) {

            alert(
                "No se pudo acceder a la carpeta."
            );

            return;

        }


        const data =
            await response.json();


        currentPath =
            data.path;


        document.getElementById(
            "currentPath"
        ).innerText =
            "/" + currentPath;


        const list =
            document.getElementById(
                "fileList"
            );


        list.innerHTML = "";


        if (
            currentPath !== ""
        ) {

            const back =
                document.createElement(
                    "div"
                );


            back.className =
                "file-item";


            back.innerHTML = `
                <div class="file-name folder">
                    📁 ..
                </div>

                <div class="file-actions">

                    <button
                    onclick="goUp()">

                    Abrir

                    </button>

                </div>
            `;


            list.appendChild(back);

        }


        for (
            const item of data.items
        ) {


            const row =
                document.createElement(
                    "div"
                );


            row.className =
                "file-item";


            const icon =
                item.type === "directory"
                ? "📁"
                : "📄";


            const className =
                item.type === "directory"
                ? "folder"
                : "file";


            let actions = "";


            if (
                item.type === "directory"
            ) {

                actions = `

                    <button
                    onclick='openFolder(${JSON.stringify(item.path)})'>

                    Abrir

                    </button>

                `;

            } else {

                actions = `

                    <button
                    onclick='downloadFile(${JSON.stringify(item.path)})'>

                    ⬇️

                    </button>

                    <button
                    onclick='deleteFile(${JSON.stringify(item.path)})'>

                    🗑️

                    </button>

                `;

            }


            row.innerHTML = `

                <div
                class="file-name ${className}">

                    ${icon}
                    ${escapeHtml(item.name)}

                </div>


                <div class="file-actions">

                    ${actions}

                </div>

            `;


            list.appendChild(row);

        }


    } catch (error) {

        console.error(error);

        alert(
            "Error cargando archivos."
        );

    }

}


function openFolder(path) {

    loadFiles(path);

}


function goUp() {

    if (!currentPath) {

        return;

    }


    const parts = currentPath.split("/").filter(Boolean);
    parts.pop();
    loadFiles(parts.join("/"));

}


function downloadFile(path) {

    window.location.href =
        "/files/download?path=" +
        encodeURIComponent(path);

}


async function deleteFile(path) {

    const confirmed =
        confirm(
            "¿Seguro que quieres eliminar este archivo?"
        );


    if (!confirmed) {

        return;

    }


    try {

        const response =
            await fetch(
                "/files/delete",
                {

                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({
                            path: path
                        })

                }
            );


        const data =
            await response.json();


        if (!data.success) {

            alert(
                data.error ||
                "No se pudo eliminar."
            );

            return;

        }


        loadFiles(currentPath);


    } catch (error) {

        console.error(error);

        alert(
            "Error eliminando archivo."
        );

    }

}


async function uploadFile() {

    const input =
        document.getElementById(
            "uploadFile"
        );


    if (
        input.files.length === 0
    ) {

        alert(
            "Selecciona un archivo."
        );

        return;

    }


    const file =
        input.files[0];


    const formData =
        new FormData();


    formData.append(
        "file",
        file
    );


    formData.append(
        "path",
        currentPath
    );


    try {

        const response =
            await fetch(
                "/files/upload",
                {

                    method: "POST",

                    body: formData

                }
            );


        const data =
            await response.json();


        if (!data.success) {

            alert(
                data.error ||
                "No se pudo subir."
            );

            return;

        }


        input.value = "";


        loadFiles(currentPath);


    } catch (error) {

        console.error(error);

        alert(
            "Error subiendo archivo."
        );

    }

}


function escapeHtml(text) {

    return text
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

}


// Cargar archivos al abrir la página

// El explorador antiguo queda desactivado; se usa pcFilesLoad().


async function changePassword() {
    const currentPassword = document.getElementById("currentPassword").value;
    const newPassword = document.getElementById("newPassword").value;
    const confirmPassword = document.getElementById("confirmPassword").value;
    const message = document.getElementById("passwordMessage");

    message.style.color = "";
    message.innerText = "";

    if (newPassword.length < 8) {
        message.innerText =
            "La nueva contraseña debe tener al menos 8 caracteres.";
        return;
    }

    if (newPassword !== confirmPassword) {
        message.innerText =
            "Las contraseñas nuevas no coinciden.";
        return;
    }

    try {
        const response = await fetch("/change-password", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword,
                confirm_password: confirmPassword
            })
        });

        const data = await response.json();

        if (!response.ok) {
            message.innerText =
                data.detail || "No se pudo cambiar la contraseña.";
            return;
        }

        message.style.color = "#4ade80";
        message.innerText = "✓ Contraseña cambiada correctamente.";

        document.getElementById("currentPassword").value = "";
        document.getElementById("newPassword").value = "";
        document.getElementById("confirmPassword").value = "";

    } catch (error) {
        message.innerText = "No se pudo conectar con el servidor.";
    }
}
</script>




<script>
// =====================================================
// MÓDULOS NUEVOS — AISLADOS DEL CONTROLADOR ORIGINAL
// =====================================================

function toggleProcessPanel() {
    const panel = document.getElementById("processPanel");
    const toggle = document.getElementById("processMenuToggle");
    if (!panel || !toggle) return;
    const open = panel.classList.toggle("process-open");
    panel.setAttribute("aria-hidden", String(!open));
    toggle.setAttribute("aria-expanded", String(open));
    if (open && typeof loadProcesses === "function") loadProcesses();
}

function togglePowerPanel() {
    const panel = document.getElementById("powerPanel");
    const toggle = document.getElementById("powerMenuToggle");
    if (!panel || !toggle) return;
    const open = panel.classList.toggle("power-open");
    panel.setAttribute("aria-hidden", String(!open));
    toggle.setAttribute("aria-expanded", String(open));
}

async function sendLocalCommand() {
    const input = document.getElementById("localAssistantText");
    const status = document.getElementById("localAssistantStatus");
    const text = (input?.value || "").trim();
    if (!text) return;
    status.textContent = "Interpretando localmente...";
    try {
        const result = await pcRemoteJson("/api/local-assistant/command", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({text})
        });
        const endpoints = {
            lock: "/api/power/lock",
            restart: "/api/power/restart",
            shutdown: "/api/power/shutdown",
            cancel: "/api/power/cancel"
        };
        if (result.action === "none") {
            status.textContent = result.reply || "No se reconoció el comando.";
            return;
        }
        if (!confirm(`${result.reply || "¿Ejecutar acción?"}\n\n¿Confirmas?`)) {
            status.textContent = "Acción cancelada por el usuario.";
            return;
        }
        await pcRemoteJson(endpoints[result.action], {method: "POST"});
        status.textContent = "✓ " + (result.reply || "Acción ejecutada.");
    } catch (error) {
        status.textContent = "Error: " + error.message;
    }
}

let pcFilesCurrentPath = "";

async function pcFilesLoad(path = "") {
    const list = document.getElementById("pcFilesList");
    const pathLabel = document.getElementById("pcFilesPath");
    if (!list || !pathLabel) return;
    list.textContent = "Cargando...";
    try {
        const data = await pcRemoteJson("/pc-files?path=" + encodeURIComponent(path));
        pcFilesCurrentPath = data.path || "";
        pathLabel.textContent = pcFilesCurrentPath || "Carpeta de usuario";
        list.innerHTML = "";
        for (const item of data.items || []) {
            const row = document.createElement("div");
            row.className = "file-item";
            const icon = item.type === "directory" ? "📁" : "📄";
            const action = item.type === "directory"
                ? `<button type="button" onclick='pcFilesLoad(${JSON.stringify(item.path)})'>Abrir</button>`
                : `<button type="button" onclick='pcFilesDownload(${JSON.stringify(item.path)})'>⬇️ Descargar</button>`;
            row.innerHTML = `<div class="file-name ${item.type === "directory" ? "folder" : "file"}">${icon} ${pcEscapeHtml(item.name)}</div><div class="file-actions">${action}</div>`;
            list.appendChild(row);
        }
    } catch (error) {
        list.textContent = "Error: " + error.message;
    }
}

function pcFilesGoUp() {
    if (!pcFilesCurrentPath) return;
    let normalized = pcFilesCurrentPath.replaceAll("\\\\", "/");
    while (normalized.endsWith("/")) normalized = normalized.slice(0, -1);
    if (/^[A-Za-z]:$/.test(normalized)) return;
    const index = normalized.lastIndexOf("/");
    pcFilesLoad(index <= 2 ? normalized.slice(0, 3) : normalized.slice(0, index));
}

function pcFilesDownload(path) {
    window.location.href = "/pc-files/download?path=" + encodeURIComponent(path);
}

async function pcFilesUpload() {
    const input = document.getElementById("pcUploadFile");
    if (!input?.files?.length) return;
    const form = new FormData();
    form.append("file", input.files[0]);
    try {
        await pcRemoteJson("/pc-files/upload?path=" + encodeURIComponent(pcFilesCurrentPath), {method: "POST", body: form});
        input.value = "";
        await pcFilesLoad(pcFilesCurrentPath);
    } catch (error) {
        alert("No se pudo subir el archivo: " + error.message);
    }
}

window.addEventListener("load", () => pcFilesLoad(""));

let localVoiceRecognition = null;

function startLocalVoice() {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    const status = document.getElementById("localAssistantStatus");
    if (!SpeechRecognition) {
        status.textContent = "Este navegador no ofrece reconocimiento de voz. Escribe el comando.";
        return;
    }
    if (localVoiceRecognition) {
        try { localVoiceRecognition.abort(); } catch (_) {}
        localVoiceRecognition = null;
    }
    const recognition = new SpeechRecognition();
    localVoiceRecognition = recognition;
    recognition.lang = "es-ES";
    recognition.interimResults = false;
    recognition.continuous = false;
    recognition.maxAlternatives = 1;
    status.textContent = "Escuchando... habla ahora.";
    recognition.onstart = () => { status.textContent = "Escuchando... habla ahora."; };
    recognition.onresult = (event) => {
        const text = event.results[0][0].transcript;
        document.getElementById("localAssistantText").value = text;
        status.textContent = "Comando recibido. Interpretando localmente...";
        sendLocalCommand();
    };
    recognition.onerror = (event) => {
        const messages = {
            "not-allowed": "Micrófono bloqueado. Permite el micrófono para esta dirección en el navegador.",
            "audio-capture": "No se encontró un micrófono disponible.",
            "no-speech": "No detecté voz. Pulsa Hablar y habla más cerca del micrófono.",
            "network": "El navegador requiere conexión/HTTPS para reconocer voz. Puedes escribir el comando.",
            "aborted": "Escucha cancelada."
        };
        status.textContent = messages[event.error] || `Error de voz: ${event.error || "desconocido"}.`;
    };
    recognition.onend = () => {
        if (localVoiceRecognition === recognition) localVoiceRecognition = null;
    };
    try {
        recognition.start();
    } catch (error) {
        localVoiceRecognition = null;
        status.textContent = "No se pudo iniciar el micrófono: " + error.message;
    }
}

async function pcRemoteJson(url, options = {}) {
    const response = await fetch(url, {
        credentials: "same-origin",
        cache: "no-store",
        ...options
    });

    const text = await response.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch (_) {}

    if (response.status === 401) {
        window.location.href = "/login";
        throw new Error("Sesión expirada.");
    }

    if (!response.ok) {
        throw new Error(data.detail || data.error || `HTTP ${response.status}`);
    }

    return data;
}

function pcFormatBytes(bytes) {
    if (!Number.isFinite(Number(bytes))) return "—";
    let value = Number(bytes);
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (value >= 1024 && i < units.length - 1) {
        value /= 1024;
        i++;
    }
    return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

async function pcLoadSystemInfo() {
    const msg = document.getElementById("pcSystemInfoMessage");
    if (!msg) return;
    msg.textContent = "Actualizando...";
    try {
        const d = await pcRemoteJson("/api/system-info");
        document.getElementById("pcNameNew").textContent = d.computer || "—";
        document.getElementById("windowsInfoNew").textContent = `${d.system || ""} ${d.release || ""}`.trim();
        document.getElementById("cpuPercentNew").textContent = `${d.cpu_percent ?? "—"}% de uso`;
        document.getElementById("cpuDetailsNew").textContent = `${d.cpu_count ?? "—"} hilos` + (d.cpu_mhz ? ` · ${d.cpu_mhz} MHz` : "");
        document.getElementById("ramPercentNew").textContent = `${d.ram?.percent ?? "—"}% usado`;
        document.getElementById("ramDetailsNew").textContent = `${pcFormatBytes(d.ram?.used)} / ${pcFormatBytes(d.ram?.total)}`;
        document.getElementById("diskPercentNew").textContent = `${d.disk?.percent ?? "—"}% usado`;
        document.getElementById("diskDetailsNew").textContent = `${pcFormatBytes(d.disk?.used)} / ${pcFormatBytes(d.disk?.total)} · ${pcFormatBytes(d.disk?.free)} libres`;
        document.getElementById("batteryInfoNew").textContent = d.battery == null ? "No disponible" : `${d.battery.percent}%${d.battery.plugged ? " · 🔌 Conectado" : ""}`;
        document.getElementById("uptimeInfoNew").textContent = d.uptime || "—";
        msg.textContent = "✓ Información actualizada.";
        msg.style.color = "#4ade80";
    } catch (e) {
        msg.textContent = "Error: " + e.message;
        msg.style.color = "#f87171";
    }
}

let pcProcesses = [];

function pcEscapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function pcRenderProcesses() {
    const body = document.getElementById("pcProcessTableBody");
    const search = (document.getElementById("pcProcessSearch")?.value || "").trim().toLowerCase();
    if (!body) return;

    const list = pcProcesses.filter(p =>
        String(p.name || "").toLowerCase().includes(search) ||
        String(p.pid || "").includes(search)
    );

    if (!list.length) {
        body.innerHTML = '<tr><td colspan="6">No hay resultados.</td></tr>';
        return;
    }

    body.innerHTML = list.map(p => `
        <tr>
            <td>${pcEscapeHtml(p.name)}</td>
            <td>${Number(p.pid)}</td>
            <td>${pcFormatBytes(p.memory)}</td>
            <td>${pcEscapeHtml(p.username || "—")}</td>
            <td>${pcEscapeHtml(p.status || "—")}</td>
            <td><button type="button" onclick="pcTerminateProcess(${Number(p.pid)})">✖ Cerrar</button></td>
        </tr>
    `).join("");
}

async function pcLoadProcesses() {
    const msg = document.getElementById("pcProcessMessage");
    if (!msg) return;
    msg.textContent = "Cargando procesos...";
    try {
        const d = await pcRemoteJson("/api/processes");
        pcProcesses = Array.isArray(d.processes) ? d.processes : [];
        pcRenderProcesses();
        msg.textContent = `✓ ${pcProcesses.length} procesos mostrados.`;
        msg.style.color = "#4ade80";
    } catch (e) {
        msg.textContent = "Error: " + e.message;
        msg.style.color = "#f87171";
    }
}

async function pcTerminateProcess(pid) {
    const process = pcProcesses.find(p => Number(p.pid) === Number(pid));
    const name = process?.name || `PID ${pid}`;
    if (!confirm(`¿Cerrar "${name}" (PID ${pid})?`)) return;

    try {
        const d = await pcRemoteJson("/api/processes/terminate", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({pid: Number(pid)})
        });
        const msg = document.getElementById("pcProcessMessage");
        msg.textContent = `✓ ${d.name || name} cerrado correctamente.`;
        msg.style.color = "#4ade80";
        await pcLoadProcesses();
    } catch (e) {
        const msg = document.getElementById("pcProcessMessage");
        msg.textContent = "Error: " + e.message;
        msg.style.color = "#f87171";
    }
}

async function pcPowerRequest(endpoint, successText) {
    const msg = document.getElementById("pcPowerMessage");
    if (msg) msg.textContent = "Enviando orden...";
    try {
        const d = await pcRemoteJson(endpoint, {method: "POST"});
        if (msg) {
            msg.textContent = d.message || successText;
            msg.style.color = "#4ade80";
        }
        return true;
    } catch (e) {
        if (msg) {
            msg.textContent = "Error: " + e.message;
            msg.style.color = "#f87171";
        }
        return false;
    }
}

async function pcLock() {
    if (confirm("¿Bloquear la sesión de Windows?")) {
        await pcPowerRequest("/api/power/lock", "✓ PC bloqueado.");
    }
}

async function pcRestart() {
    if (confirm("⚠️ ¿Reiniciar el PC?")) {
        await pcPowerRequest("/api/power/restart", "✓ Reinicio programado.");
    }
}

async function pcShutdown() {
    if (confirm("⚠️ ¿Apagar el PC?")) {
        await pcPowerRequest("/api/power/shutdown", "✓ Apagado programado.");
    }
}

async function pcCancelPower() {
    await pcPowerRequest("/api/power/cancel", "✓ Acción cancelada.");
}
</script>





<!-- =====================================================
     INFORMACIÓN DEL PC
===================================================== -->
<section class="pc-info-section">
    <h2>📊 Información del PC</h2>
    <div class="pc-info-grid">
        <div class="info-card"><b>🖥️ Equipo</b><span id="pcName">—</span><span id="windowsInfo">—</span></div>
        <div class="info-card"><b>🧠 CPU</b><span id="cpuPercent">—</span><span id="cpuDetails">—</span></div>
        <div class="info-card"><b>💾 RAM</b><span id="ramPercent">—</span><span id="ramDetails">—</span></div>
        <div class="info-card"><b>💽 Disco</b><span id="diskPercent">—</span><span id="diskDetails">—</span></div>
        <div class="info-card"><b>🔋 Batería</b><span id="batteryInfo">—</span></div>
        <div class="info-card"><b>⏱️ Tiempo encendido</b><span id="uptimeInfo">—</span></div>
    </div>
    <button onclick="loadSystemInfo()">🔄 Actualizar información</button>
    <div id="systemInfoMessage"></div>
</section>
<style>
.pc-info-section{width:95%;max-width:1100px;margin:25px auto}
.pc-info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:15px 0}
.info-card{background:#1b1b1b;border:1px solid #444;border-radius:12px;padding:16px;text-align:left;min-height:105px}
.info-card b{display:block;margin-bottom:12px;font-size:17px}
.info-card span{display:block;margin:5px 0;color:#ccc}
.pc-info-section>button{width:100%;max-width:400px;padding:12px;border-radius:8px;border:1px solid #555;background:#292929;color:white;font-size:16px}
#systemInfoMessage{min-height:22px;margin-top:10px}
</style>

<!-- =====================================================
     ADMINISTRADOR DE PROCESOS
===================================================== -->
<button id="processMenuToggle" class="process-menu-toggle" type="button"
        onclick="toggleProcessPanel()" aria-controls="processPanel" aria-expanded="false">
    ⚙️ Procesos
</button>

<aside id="processPanel" class="process-section" aria-hidden="true">
<button class="process-panel-close" type="button" onclick="toggleProcessPanel()">
    ✕ Cerrar panel
</button>
<h2>⚙️ Procesos</h2>
<div class="process-toolbar">
<button onclick="loadProcesses()">🔄 Actualizar</button>
<input id="processSearch" type="search" placeholder="Buscar proceso..." oninput="renderProcesses()">
</div>
<div id="processMessage"></div>
<div class="process-table-wrapper">
<table class="process-table">
<thead><tr><th>Proceso</th><th>PID</th><th>Memoria</th><th>Usuario</th><th>Estado</th><th>Acción</th></tr></thead>
<tbody id="processTableBody"><tr><td colspan="6">Pulsa "Actualizar".</td></tr></tbody>
</table>
</div>
</aside>
<style>
.process-menu-toggle{position:fixed;top:12px;right:12px;z-index:1100;padding:10px 14px;background:#202a3a;border-color:#4b6b95;box-shadow:0 5px 18px rgba(0,0,0,.35)}
.process-section{position:fixed;top:0;right:0;z-index:1050;width:min(96vw,1200px);height:100vh;margin:0;padding:72px 22px 24px;overflow:auto;text-align:left;background:#121212;border-left:1px solid #444;box-shadow:-12px 0 35px rgba(0,0,0,.45);transform:translateX(102%);transition:transform .22s ease-in-out}
.process-section.process-open{transform:translateX(0)}
.process-panel-close{position:absolute;top:14px;left:22px;padding:8px 12px;font-size:13px}
.process-section h2{text-align:left}
.process-toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:15px 0}
.process-toolbar button,.process-toolbar input{padding:11px;border-radius:8px;border:1px solid #555;background:#222;color:white;font-size:15px}
.process-toolbar input{flex:1;min-width:220px}
.process-table-wrapper{width:100%;overflow-x:auto;border:1px solid #444;border-radius:10px;background:#171717}
.process-table{width:100%;border-collapse:collapse;min-width:760px}
.process-table th,.process-table td{padding:10px;border-bottom:1px solid #333;text-align:left}
.process-table th{background:#222}
.process-kill{padding:7px 10px;border-radius:7px;border:1px solid #666;background:#302020;color:white}
#processMessage{min-height:22px;margin:8px 0}
@media (max-width:600px){.process-menu-toggle{top:8px;right:8px}.process-section{width:100vw;padding:66px 12px 20px}.process-panel-close{left:12px}}
</style>

<!-- =====================================================
     CONTROLES DE ENERGÍA
===================================================== -->

<button id="powerMenuToggle" class="power-menu-toggle" type="button"
        onclick="togglePowerPanel()" aria-controls="powerPanel" aria-expanded="false">
    ⚡ Control del PC
</button>

<aside id="powerPanel" class="power-section" aria-hidden="true">
    <button class="power-panel-close" type="button" onclick="togglePowerPanel()">✕ Cerrar panel</button>
    <h2>⚡ Control del PC</h2>

    <div class="power-grid">

        <button
            class="power-button lock"
            onclick="lockPC()"
        >
            🔒
            <strong>Bloquear</strong>
            <span>Bloquea la sesión de Windows</span>
        </button>

        <button
            class="power-button restart"
            onclick="restartPC()"
        >
            🔄
            <strong>Reiniciar</strong>
            <span>Reinicia el PC</span>
        </button>

        <button
            class="power-button shutdown"
            onclick="shutdownPC()"
        >
            ⏻
            <strong>Apagar</strong>
            <span>Apaga el PC</span>
        </button>

    </div>

    <div id="powerMessage"></div>
</aside>

<style>
.power-section {
    position: fixed;
    top: 0;
    right: 0;
    z-index: 1050;
    width: min(92vw, 520px);
    height: 100vh;
    margin: 0;
    padding: 72px 22px 24px;
    overflow: auto;
    background: #121212;
    border-left: 1px solid #444;
    box-shadow: -12px 0 35px rgba(0,0,0,.45);
    transform: translateX(102%);
    transition: transform .22s ease-in-out;
    text-align: left;
}
.power-section.power-open { transform: translateX(0); }
.power-menu-toggle { position: fixed; top: 12px; left: 12px; z-index: 1100; padding: 10px 14px; background: #3a2d20; border-color: #8b6b45; }
.power-panel-close { position: absolute; top: 14px; left: 22px; padding: 8px 12px; font-size: 13px; }
@media (max-width:600px) { .power-menu-toggle { top: 8px; left: 8px; } .power-section { width: 100vw; padding: 66px 12px 20px; } .power-panel-close { left: 12px; } }
}

.power-grid {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(210px, 1fr));
    gap: 14px;
    margin-top: 15px;
}

.power-button {
    min-height: 145px;
    padding: 18px;
    border-radius: 14px;
    border: 1px solid #555;
    background: #1b1b1b;
    color: white;
    cursor: pointer;

    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 8px;

    font-size: 30px;
}

.power-button strong {
    font-size: 18px;
}

.power-button span {
    font-size: 13px;
    color: #aaa;
}

.power-button:hover {
    background: #292929;
}

#powerMessage {
    min-height: 24px;
    margin-top: 12px;
}
</style>

<script>
/* ==========================================================
   PC REMOTE - CONTROLES FINALES
   Conecta los nombres de los botones con los endpoints reales.
========================================================== */

(function () {
    "use strict";

    async function pcRequest(url, options) {
        const opts = Object.assign(
            {
                credentials: "same-origin",
                cache: "no-store"
            },
            options || {}
        );

        const response = await fetch(url, opts);
        const text = await response.text();

        let data = {};
        try {
            data = text ? JSON.parse(text) : {};
        } catch (_) {}

        if (response.status === 401) {
            window.location.href = "/login";
            throw new Error("Sesión no autenticada.");
        }

        if (!response.ok) {
            throw new Error(
                data.detail ||
                data.error ||
                ("HTTP " + response.status)
            );
        }

        return data;
    }

    function setMessage(id, text, ok) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = text;
        el.style.color = ok ? "#4ade80" : "#f87171";
    }

    function formatBytes(bytes) {
        let value = Number(bytes);
        if (!Number.isFinite(value)) return "—";

        const units = ["B", "KB", "MB", "GB", "TB"];
        let index = 0;

        while (
            value >= 1024 &&
            index < units.length - 1
        ) {
            value /= 1024;
            index++;
        }

        return (
            value.toFixed(index === 0 ? 0 : 1) +
            " " +
            units[index]
        );
    }

    function escapeHtml(value) {
        return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    /* ------------------------------------------------------
       INFORMACIÓN DEL PC
    ------------------------------------------------------ */

    window.loadSystemInfo = async function () {
        const message = document.getElementById(
            "systemInfoMessage"
        );

        if (message) {
            message.textContent =
                "Actualizando información...";
            message.style.color = "";
        }

        try {
            const data = await pcRequest(
                "/api/system-info"
            );

            document.getElementById("pcName").textContent =
                data.computer || "—";

            document.getElementById("windowsInfo").textContent =
                (
                    (data.system || "") +
                    " " +
                    (data.release || "")
                ).trim();

            document.getElementById("cpuPercent").textContent =
                (data.cpu_percent ?? "—") +
                "% de uso";

            document.getElementById("cpuDetails").textContent =
                (data.cpu_count ?? "—") +
                " hilos" +
                (
                    data.cpu_mhz
                        ? " · " + data.cpu_mhz + " MHz"
                        : ""
                );

            document.getElementById("ramPercent").textContent =
                (data.ram?.percent ?? "—") +
                "% usado";

            document.getElementById("ramDetails").textContent =
                formatBytes(data.ram?.used) +
                " / " +
                formatBytes(data.ram?.total);

            document.getElementById("diskPercent").textContent =
                (data.disk?.percent ?? "—") +
                "% usado";

            document.getElementById("diskDetails").textContent =
                formatBytes(data.disk?.used) +
                " / " +
                formatBytes(data.disk?.total) +
                " · " +
                formatBytes(data.disk?.free) +
                " libres";

            document.getElementById("batteryInfo").textContent =
                data.battery == null
                    ? "No disponible"
                    : (
                        data.battery.percent +
                        "%" +
                        (
                            data.battery.plugged
                                ? " · 🔌 Conectado"
                                : ""
                        )
                    );

            document.getElementById("uptimeInfo").textContent =
                data.uptime || "—";

            setMessage(
                "systemInfoMessage",
                "✓ Información actualizada.",
                true
            );
        } catch (error) {
            setMessage(
                "systemInfoMessage",
                "Error: " + error.message,
                false
            );
        }
    };

    /* ------------------------------------------------------
       PROCESOS
    ------------------------------------------------------ */

    let processList = [];

    window.renderProcesses = function () {
        const body = document.getElementById(
            "processTableBody"
        );

        if (!body) return;

        const search =
            (
                document.getElementById(
                    "processSearch"
                )?.value || ""
            )
            .trim()
            .toLowerCase();

        const filtered = processList.filter(
            function (process) {
                return (
                    String(process.name || "")
                        .toLowerCase()
                        .includes(search)
                    ||
                    String(process.pid || "")
                        .includes(search)
                );
            }
        );

        if (!filtered.length) {
            body.innerHTML =
                '<tr><td colspan="6">' +
                "No hay resultados." +
                "</td></tr>";
            return;
        }

        body.innerHTML = filtered.map(
            function (process) {
                const name = escapeHtml(
                    process.name || "Desconocido"
                );

                const username = escapeHtml(
                    process.username || "—"
                );

                const status = escapeHtml(
                    process.status || "—"
                );

                return `
                    <tr>
                        <td>${name}</td>
                        <td>${Number(process.pid)}</td>
                        <td>${formatBytes(process.memory)}</td>
                        <td>${username}</td>
                        <td>${status}</td>
                        <td>
                            <button
                                type="button"
                                class="process-kill"
                                onclick="terminateProcess(${Number(process.pid)})"
                            >
                                ✖ Cerrar
                            </button>
                        </td>
                    </tr>
                `;
            }
        ).join("");
    };

    window.loadProcesses = async function () {
        setMessage(
            "processMessage",
            "Cargando procesos...",
            true
        );

        try {
            const data = await pcRequest(
                "/api/processes"
            );

            processList =
                Array.isArray(data.processes)
                    ? data.processes
                    : [];

            window.renderProcesses();

            setMessage(
                "processMessage",
                "✓ " +
                processList.length +
                " procesos mostrados.",
                true
            );
        } catch (error) {
            setMessage(
                "processMessage",
                "Error: " + error.message,
                false
            );
        }
    };

    window.terminateProcess = async function (pid) {
        const process = processList.find(
            function (item) {
                return Number(item.pid) === Number(pid);
            }
        );

        const name =
            process?.name ||
            ("PID " + pid);

        if (
            !confirm(
                '¿Seguro que quieres cerrar "' +
                name +
                '" (PID ' +
                pid +
                ")?"
            )
        ) {
            return;
        }

        try {
            const data = await pcRequest(
                "/api/processes/terminate",
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    body: JSON.stringify({
                        pid: Number(pid)
                    })
                }
            );

            setMessage(
                "processMessage",
                "✓ " +
                (data.name || name) +
                " cerrado correctamente.",
                true
            );

            await window.loadProcesses();
        } catch (error) {
            setMessage(
                "processMessage",
                "Error: " + error.message,
                false
            );
        }
    };

    /* ------------------------------------------------------
       ENERGÍA
    ------------------------------------------------------ */

    async function powerRequest(endpoint, defaultMessage) {
        const messageId = "powerMessage";

        setMessage(
            messageId,
            "Enviando orden...",
            true
        );

        try {
            const data = await pcRequest(
                endpoint,
                {
                    method: "POST"
                }
            );

            setMessage(
                messageId,
                data.message || defaultMessage,
                true
            );

            return true;
        } catch (error) {
            setMessage(
                messageId,
                "Error: " + error.message,
                false
            );

            return false;
        }
    }

    window.lockPC = async function () {
        if (!confirm(
            "¿Seguro que quieres BLOQUEAR Windows?"
        )) {
            return;
        }

        await powerRequest(
            "/api/power/lock",
            "✓ PC bloqueado."
        );
    };

    window.restartPC = async function () {
        if (!confirm(
            "⚠️ ¿Seguro que quieres REINICIAR el PC?"
        )) {
            return;
        }

        await powerRequest(
            "/api/power/restart",
            "✓ Reinicio programado."
        );
    };

    window.shutdownPC = async function () {
        if (!confirm(
            "⚠️ ¿Seguro que quieres APAGAR el PC?"
        )) {
            return;
        }

        await powerRequest(
            "/api/power/shutdown",
            "✓ Apagado programado."
        );
    };

    window.cancelPowerAction = async function () {
        await powerRequest(
            "/api/power/cancel",
            "✓ Acción cancelada."
        );
    };

    /* ------------------------------------------------------
       DIAGNÓSTICO / ARRANQUE
    ------------------------------------------------------ */

    window.pcRemoteTest = async function () {
        try {
            await pcRequest("/api/system-info");
            return true;
        } catch (_) {
            return false;
        }
    };

    window.addEventListener(
        "DOMContentLoaded",
        function () {
            // Cargar automáticamente la información y procesos.
            window.loadSystemInfo();
            window.loadProcesses();
        }
    );
})();
</script>

</body>

</html>

"""



# ==========================================================
# SYSTEM_INFO_MODULE_V1
# ==========================================================

def get_system_info():
    memory = psutil.virtual_memory()
    root = Path.home().anchor or "C:\\"
    disk = psutil.disk_usage(root)

    try:
        battery = psutil.sensors_battery()
    except Exception:
        battery = None

    uptime_seconds = max(0, int(time.time() - psutil.boot_time()))
    days, rem = divmod(uptime_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60

    try:
        cpu_percent = psutil.cpu_percent(interval=0.2)
    except Exception:
        cpu_percent = 0

    freq = None
    try:
        freq = psutil.cpu_freq()
    except Exception:
        pass

    return {
        "computer": platform.node() or "PC",
        "system": platform.system(),
        "release": platform.release(),
        "processor": platform.processor() or "Desconocido",
        "cpu_percent": cpu_percent,
        "cpu_count": psutil.cpu_count(logical=True) or 0,
        "cpu_mhz": round(freq.current) if freq else 0,
        "ram": {
            "used": memory.used,
            "total": memory.total,
            "percent": memory.percent
        },
        "disk": {
            "used": disk.used,
            "total": disk.total,
            "free": disk.free,
            "percent": disk.percent
        },
        "battery": (
            None if battery is None else {
                "percent": round(battery.percent, 1),
                "plugged": bool(battery.power_plugged)
            }
        ),
        "uptime": f"{days}d {hours}h {minutes}m"
    }


@app.get("/api/system-info")
def system_info(request: Request):
    require_session(request)
    return get_system_info()



# ==========================================================
# PROCESS_MANAGER_MODULE_V1
# ==========================================================

@app.get("/api/processes")
def list_processes(request: Request):
    require_session(request)
    result = []
    for proc in psutil.process_iter(["pid","name","username","status","memory_info"]):
        try:
            info=proc.info
            mem=info.get("memory_info")
            result.append({
                "pid": info.get("pid"),
                "name": info.get("name") or "Desconocido",
                "username": info.get("username") or "",
                "status": info.get("status") or "",
                "memory": mem.rss if mem else 0
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue
    result.sort(key=lambda x:x["memory"], reverse=True)
    return {"processes": result[:250]}


@app.post("/api/processes/terminate")
async def terminate_process(request: Request):
    require_session(request)
    try:
        data=await request.json()
        pid=int(data.get("pid"))
    except Exception:
        raise HTTPException(status_code=400, detail="PID inválido.")

    if pid <= 0 or pid == os.getpid():
        raise HTTPException(status_code=400, detail="PID no permitido.")

    protected={
        "System","System Idle Process","Registry",
        "smss.exe","csrss.exe","wininit.exe",
        "services.exe","lsass.exe","winlogon.exe"
    }

    try:
        proc=psutil.Process(pid)
        name=proc.name()

        if name in protected:
            raise HTTPException(status_code=403,
                                detail=f"Proceso protegido: {name}")

        proc.terminate()
        try:
            proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            proc.kill()

        return {"success":True,"pid":pid,"name":name}

    except psutil.NoSuchProcess:
        raise HTTPException(status_code=404, detail="El proceso ya no existe.")
    except psutil.AccessDenied:
        raise HTTPException(status_code=403,
                            detail="Windows no permite cerrar este proceso.")



# ==========================================================
# POWER_CONTROLS_MODULE_V1
# BLOQUEAR / REINICIAR / APAGAR
# ==========================================================

@app.post("/api/power/lock")
def lock_pc(request: Request):
    require_session(request)

    try:
        import ctypes
        result = ctypes.windll.user32.LockWorkStation()

        if not result:
            raise RuntimeError("Windows no pudo bloquear la sesión.")

        return {"success": True, "action": "lock"}

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"No se pudo bloquear Windows: {exc}"
        )


@app.post("/api/power/restart")
def restart_pc(request: Request):
    require_session(request)

    try:
        subprocess.Popen(
            [
                "shutdown",
                "/r",
                "/t",
                "5",
                "/d",
                "p:0:0"
            ],
            creationflags=getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0
            )
        )

        return {
            "success": True,
            "action": "restart",
            "message": "El PC se reiniciará en 5 segundos."
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"No se pudo iniciar el reinicio: {exc}"
        )


@app.post("/api/power/shutdown")
def shutdown_pc(request: Request):
    require_session(request)

    try:
        subprocess.Popen(
            [
                "shutdown",
                "/s",
                "/t",
                "5",
                "/d",
                "p:0:0"
            ],
            creationflags=getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0
            )
        )

        return {
            "success": True,
            "action": "shutdown",
            "message": "El PC se apagará en 5 segundos."
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"No se pudo iniciar el apagado: {exc}"
        )


@app.post("/api/power/cancel")
def cancel_power_action(request: Request):
    require_session(request)

    try:
        subprocess.Popen(
            [
                "shutdown",
                "/a"
            ],
            creationflags=getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0
            )
        )

        return {
            "success": True,
            "message": "La acción pendiente fue cancelada."
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"No se pudo cancelar la acción: {exc}"
        )


# ==========================================================
# PÁGINA PRINCIPAL
# ==========================================================

@app.get(
    "/",
    response_class=HTMLResponse
)
def home():

    return HTML


# ==========================================================
# PANTALLA
# ==========================================================

import numpy as np

# Capturador compartido — se inicializa una vez, evita overhead por petición
_sct = None
_monitor = None

def _get_sct():
    global _sct, _monitor
    if _sct is None:
        _sct = mss.mss()
        _monitor = _sct.monitors[1]
    return _sct, _monitor

SCREEN_SCALE   = 0.55   # resolución: 55% del original
SCREEN_QUALITY = 45     # JPEG quality — balance velocidad/calidad
_ENCODE_PARAMS = [int(cv2.IMWRITE_JPEG_QUALITY), SCREEN_QUALITY]

@app.get("/frame")
def get_frame():
    """Devuelve UN solo frame JPEG. El cliente llama esto en loop."""
    try:
        sct, monitor = _get_sct()
        raw = sct.grab(monitor)
        frame = np.frombuffer(raw.raw, dtype=np.uint8).reshape(
            raw.height, raw.width, 4
        )[:, :, :3]
        w = int(raw.width * SCREEN_SCALE)
        h = int(raw.height * SCREEN_SCALE)
        frame = cv2.resize(frame, (w, h), interpolation=cv2.INTER_LINEAR)
        ok, encoded = cv2.imencode(".jpg", frame, _ENCODE_PARAMS)
        if not ok:
            raise HTTPException(status_code=500, detail="encode error")
        return Response(
            content=encoded.tobytes(),
            media_type="image/jpeg",
            headers={
                "Cache-Control": "no-store",
                "X-Frame-Width": str(w),
                "X-Frame-Height": str(h),
            }
        )
    except Exception:
        # Si el capturador falló, resetear para que se reinicie en la siguiente petición
        global _sct, _monitor
        _sct = None
        _monitor = None
        raise HTTPException(status_code=500, detail="capture error")

# Mantener /screen por compatibilidad (redirige al frame)
@app.get("/screen")
def screen():
    return get_frame()



# ==========================================================
# CÁMARA
# ==========================================================

def generate_camera():
    camera = cv2.VideoCapture(0, cv2.CAP_DSHOW)
    if not camera.isOpened():
        return
    try:
        # Resolución baja → mucho más fluido por red
        camera.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        camera.set(cv2.CAP_PROP_FPS, 30)
        camera.set(cv2.CAP_PROP_BUFFERSIZE, 1)  # buffer mínimo → sin lag acumulado
        encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), 50]
        while True:
            success, frame = camera.read()
            if not success:
                break
            ok, encoded = cv2.imencode(".jpg", frame, encode_params)
            if not ok:
                continue
            yield (
                b"--frame\r\nContent-Type: image/jpeg\r\n\r\n"
                + encoded.tobytes()
                + b"\r\n"
            )
    except (GeneratorExit, KeyboardInterrupt, asyncio.CancelledError):
        return
    finally:
        try:
            camera.release()
        except Exception:
            pass


@app.get("/camera")
def camera_endpoint():

    return StreamingResponse(
        generate_camera(),
        media_type="multipart/x-mixed-replace; boundary=frame"
    )


# ==========================================================
# MOUSE
# ==========================================================

@app.post("/mouse/move")
async def mouse_move(
    request: Request
):

    data = await request.json()

    x = float(data["x"])
    y = float(data["y"])

    client_width = float(
        data["width"]
    )

    client_height = float(
        data["height"]
    )

    screen_width, screen_height = (
        pyautogui.size()
    )

    real_x = int(
        (x / client_width)
        * screen_width
    )

    real_y = int(
        (y / client_height)
        * screen_height
    )

    real_x = max(
        0,
        min(
            real_x,
            screen_width - 1
        )
    )

    real_y = max(
        0,
        min(
            real_y,
            screen_height - 1
        )
    )

    pyautogui.moveTo(
        real_x,
        real_y
    )

    return {
        "success": True
    }


@app.post("/mouse/click")
async def mouse_click(
    request: Request
):

    data = await request.json()

    button = data.get(
        "button",
        "left"
    )

    if button not in [
        "left",
        "right"
    ]:

        return {
            "success": False
        }

    pyautogui.click(
        button=button
    )

    return {
        "success": True
    }


# ==========================================================
# TECLADO
# ==========================================================

ALLOWED_KEYS = {

    "escape",
    "tab",
    "enter",
    "backspace",
    "space",

    "shift",
    "ctrl",
    "alt",
    "win",

    "capslock",

    "left",
    "right",
    "up",
    "down",

    "f1",
    "f2",
    "f3",
    "f4",
    "f5",
    "f6",
    "f7",
    "f8",
    "f9",
    "f10",
    "f11",
    "f12",

    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",

    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",

    "-",
    "=",
    "[",
    "]",
    ";",
    ",",
    "."
}


@app.post("/keyboard/key")
async def keyboard_key(
    request: Request
):

    data = await request.json()

    key = str(
        data.get(
            "key",
            ""
        )
    )

    if key not in ALLOWED_KEYS:

        return {
            "success": False
        }

    pyautogui.press(key)

    return {
        "success": True
    }


@app.post("/keyboard/text")
async def keyboard_text(
    request: Request
):

    data = await request.json()

    text = str(
        data.get(
            "text",
            ""
        )
    )

    if len(text) > 500:

        return {
            "success": False,
            "error":
                "Texto demasiado largo"
        }

    if text:

        pyautogui.write(
            text,
            interval=0.01
        )

    return {
        "success": True
    }


# ==========================================================
# LISTAR ARCHIVOS
# ==========================================================

PC_FILE_HOME = Path.home().resolve()


def pc_file_roots():
    roots = []
    if os.name == "nt":
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            candidate = Path(f"{letter}:\\")
            if candidate.exists():
                roots.append(candidate.resolve())
    return roots or [PC_FILE_HOME]


def safe_pc_file_path(value: str = "") -> Path:
    raw = str(value or "").strip().replace("\\", "/")
    requested = PC_FILE_HOME if not raw else Path(raw)
    if not requested.is_absolute():
        requested = PC_FILE_HOME / raw
    requested = requested.resolve()
    if not any(requested == root or root in requested.parents for root in pc_file_roots()):
        raise HTTPException(status_code=403, detail="Ruta no permitida")
    return requested


@app.get("/pc-files")
def list_pc_files(path: str = ""):
    folder = safe_pc_file_path(path)
    if not folder.exists() or not folder.is_dir():
        raise HTTPException(status_code=400, detail="Carpeta no válida")
    try:
        entries = sorted(folder.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
    except PermissionError:
        raise HTTPException(status_code=403, detail="Windows denegó el acceso a esta carpeta")
    items = []
    for item in entries:
        try:
            kind = "directory" if item.is_dir() else "file"
        except OSError:
            continue
        items.append({"name": item.name, "path": item.as_posix(), "type": kind})
    return {"path": folder.as_posix(), "items": items}


@app.get("/pc-files/download")
def download_pc_file(path: str):
    file_path = safe_pc_file_path(path)
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    return FileResponse(path=file_path, filename=file_path.name)


@app.post("/pc-files/upload")
async def upload_pc_file(path: str = "", file: UploadFile = File(...)):
    folder = safe_pc_file_path(path)
    if not folder.exists() or not folder.is_dir():
        raise HTTPException(status_code=400, detail="Destino inválido")
    filename = Path(file.filename or "archivo").name
    destination = safe_pc_file_path(str(folder / filename))
    with destination.open("wb") as output:
        while chunk := await file.read(1024 * 1024):
            output.write(chunk)
    return {"success": True, "filename": filename}

@app.get("/files")
def list_files(
    path: str = ""
):

    folder = safe_path(path)


    if not folder.exists():

        raise HTTPException(
            status_code=404,
            detail="Carpeta no encontrada"
        )


    if not folder.is_dir():

        raise HTTPException(
            status_code=400,
            detail="No es una carpeta"
        )


    items = []


    for item in sorted(
        folder.iterdir(),
        key=lambda x: (not x.is_dir(), x.name.lower())
    ):
        relative = item.relative_to(REMOTE_ROOT).as_posix()
        items.append({
            "name": item.name,
            "path": relative,
            "type": "directory" if item.is_dir() else "file"
        })


    return {

        "path": Path(path).as_posix() if path else "",

        "items": items

    }


# ==========================================================
# DESCARGAR
# ==========================================================

@app.get("/files/download")
def download_file(
    path: str
):

    file_path = safe_path(path)


    if not file_path.exists():

        raise HTTPException(
            status_code=404,
            detail="Archivo no encontrado"
        )


    if not file_path.is_file():

        raise HTTPException(
            status_code=400,
            detail="No es un archivo"
        )


    return FileResponse(
        path=file_path,
        filename=file_path.name
    )


# ==========================================================
# SUBIR
# ==========================================================

@app.post("/files/upload")
async def upload_file(
    path: str = "",
    file: UploadFile = File(...)
):

    folder = safe_path(path)


    if not folder.exists():

        raise HTTPException(
            status_code=404,
            detail="Carpeta no encontrada"
        )


    if not folder.is_dir():

        raise HTTPException(
            status_code=400,
            detail="Destino inválido"
        )


    filename = Path(
        file.filename
    ).name


    destination = safe_path(
            str(
                Path(path) /
                filename
            )
        )


    with destination.open(
        "wb"
    ) as output:

        while True:

            chunk = await file.read(
                    1024 * 1024
                )

            if not chunk:

                break

            output.write(
                chunk
            )


    return {
        "success": True,
        "filename": filename
    }


# ==========================================================
# ELIMINAR
# ==========================================================

@app.post("/files/delete")
async def delete_file(
    request: Request
):

    data = await request.json()


    path = str(
            data.get(
                "path",
                ""
            )
        )


    target = safe_path(path)


    if not target.exists():

        return {
            "success": False,
            "error":
                "El archivo no existe"
        }


    # Por seguridad no permitimos
    # eliminar la carpeta raíz.

    if target == REMOTE_ROOT:

        return {
            "success": False,
            "error":
                "No puedes eliminar la raíz"
        }


    if target.is_dir():

        shutil.rmtree(
            target
        )

    else:

        target.unlink()


    return {
        "success": True
    }

# ==========================================================
# CREAR CARPETA
# ==========================================================

@app.post("/files/create-folder")
async def create_folder(request: Request):

    data = await request.json()

    parent = str(data.get("path", ""))
    name = str(data.get("name", "")).strip()

    if not name:
        return {
            "success": False,
            "error": "Nombre vacío"
        }

    if "/" in name or "\\" in name:
        return {
            "success": False,
            "error": "Nombre de carpeta no válido"
        }

    parent_path = safe_path(parent)

    if not parent_path.is_dir():
        return {
            "success": False,
            "error": "La ubicación no es una carpeta"
        }

    new_folder = safe_path(
        str(Path(parent) / name)
    )

    if new_folder.exists():
        return {
            "success": False,
            "error": "Ya existe un elemento con ese nombre"
        }

    new_folder.mkdir()

    return {
        "success": True
    }


# ==========================================================
# CREAR ARCHIVO
# ==========================================================

@app.post("/files/create-file")
async def create_file(request: Request):

    data = await request.json()

    parent = str(data.get("path", ""))
    name = str(data.get("name", "")).strip()

    if not name:
        return {
            "success": False,
            "error": "Nombre vacío"
        }

    if "/" in name or "\\" in name:
        return {
            "success": False,
            "error": "Nombre de archivo no válido"
        }

    parent_path = safe_path(parent)

    if not parent_path.is_dir():
        return {
            "success": False,
            "error": "La ubicación no es válida"
        }

    new_file = safe_path(
        str(Path(parent) / name)
    )

    if new_file.exists():
        return {
            "success": False,
            "error": "Ya existe un elemento con ese nombre"
        }

    new_file.touch()

    return {
        "success": True
    }


# ==========================================================
# RENOMBRAR
# ==========================================================

@app.post("/files/rename")
async def rename_file(request: Request):

    data = await request.json()

    old_path = str(
        data.get("path", "")
    )

    new_name = str(
        data.get("name", "")
    ).strip()

    if not new_name:
        return {
            "success": False,
            "error": "Nombre vacío"
        }

    if "/" in new_name or "\\" in new_name:
        return {
            "success": False,
            "error": "Nombre no válido"
        }

    source = safe_path(old_path)

    if not source.exists():
        return {
            "success": False,
            "error": "El elemento no existe"
        }

    destination = safe_path(
        str(
            Path(old_path).parent /
            new_name
        )
    )

    if destination.exists():
        return {
            "success": False,
            "error": "Ya existe un elemento con ese nombre"
        }

    source.rename(destination)

    return {
        "success": True
    }


# ==========================================================
# COPIAR
# ==========================================================

@app.post("/files/copy")
async def copy_file(request: Request):

    data = await request.json()

    source_path = str(
        data.get("source", "")
    )

    destination_path = str(
        data.get("destination", "")
    )

    source = safe_path(source_path)
    destination = safe_path(destination_path)

    if not source.exists():
        return {
            "success": False,
            "error": "El origen no existe"
        }

    if not destination.is_dir():
        return {
            "success": False,
            "error": "El destino no es una carpeta"
        }

    target = destination / source.name

    if target.exists():
        return {
            "success": False,
            "error": "Ya existe un elemento con ese nombre"
        }

    if source.is_dir():

        shutil.copytree(
            source,
            target
        )

    else:

        shutil.copy2(
            source,
            target
        )

    return {
        "success": True
    }


# ==========================================================
# MOVER
# ==========================================================

@app.post("/files/move")
async def move_file(request: Request):

    data = await request.json()

    source_path = str(
        data.get("source", "")
    )

    destination_path = str(
        data.get("destination", "")
    )

    source = safe_path(source_path)
    destination = safe_path(destination_path)

    if not source.exists():
        return {
            "success": False,
            "error": "El origen no existe"
        }

    if not destination.is_dir():
        return {
            "success": False,
            "error": "El destino no es una carpeta"
        }

    target = destination / source.name

    if target.exists():
        return {
            "success": False,
            "error": "Ya existe un elemento con ese nombre"
        }

    shutil.move(
        str(source),
        str(target)
    )

    return {
        "success": True
    }

# ==========================================================
# SERVIDOR
# ==========================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        loop="asyncio",
        http="h11",
        log_level="warning",   # menos I/O de logs → más CPU para streaming
        timeout_keep_alive=60,
    )
