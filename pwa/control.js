const STORAGE_KEY = "pcremote.connections.v1";
const query = new URLSearchParams(location.search);
const index = Number(query.get("pc"));
const connections = (() => { try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"); } catch (_) { return []; } })();
const connection = Number.isInteger(index) ? connections[index] : null;
const $ = id => document.getElementById(id);
let cameraController = null;
let cameraObjectUrl = null;

function notice(message) { $("notice").hidden = !message; $("notice").textContent = message || ""; }
function headers(extra = {}) { return {...extra, Authorization: `Bearer ${connection.token}`}; }
async function request(path, options = {}) {
  if (!connection?.endpoint || !connection?.token) throw new Error("La conexión no está disponible.");
  const response = await fetch(`${connection.endpoint}${path}`, {...options, headers: headers(options.headers || {}), cache: "no-store"});
  const text = await response.text(); let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch (_) {}
  if (!response.ok) throw new Error(data.detail || data.error || `HTTP ${response.status}`);
  return data;
}
async function refreshInfo() {
  try {
    const data = await request("/api/system-info");
    $("title").textContent = connection.name || data.computer || "Control";
    $("connectionState").textContent = "● Conectado";
    $("connectionState").classList.remove("offline");
    $("systemInfo").innerHTML = `<span><b>Equipo</b>${escapeHtml(data.computer || "-")}</span><span><b>CPU</b>${escapeHtml(String(data.cpu_percent ?? "-"))}%</span><span><b>Memoria</b>${escapeHtml(String(data.ram?.percent ?? "-"))}%</span><span><b>Disco</b>${escapeHtml(String(data.disk?.percent ?? "-"))}%</span>`;
    await refreshScreen();
  } catch (error) { $("connectionState").textContent = "● Sin conexión"; $("connectionState").classList.add("offline"); notice(error.message); }
}
async function refreshScreen() {
  try { const response = await fetch(`${connection.endpoint}/frame`, {headers: headers()}); if (!response.ok) throw new Error("No se pudo obtener la pantalla."); const blob = await response.blob(); const old = $("screen").src; const url = URL.createObjectURL(blob); $("screen").src = url; $("screen").hidden = false; $("screenEmpty").hidden = true; if (old.startsWith("blob:")) URL.revokeObjectURL(old); } catch (_) { $("screen").hidden = true; $("screenEmpty").hidden = false; }
}
async function send(path, options = {}) { try { const data = await request(path, options); notice(data.message || "Acción enviada."); } catch (error) { notice(error.message); } }
function escapeHtml(value) { return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;"); }
function formatBytes(value) { const n = Number(value); if (!Number.isFinite(n)) return ""; if (n < 1024) return `${n} B`; if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`; return `${(n / 1024 ** 2).toFixed(1)} MB`; }

async function loadProcesses() {
  const target = $("processList"); target.innerHTML = "Cargando…";
  try {
    const data = await request("/api/processes");
    const filter = $("processFilter").value.trim().toLowerCase();
    const rows = (data.processes || []).filter(item => !filter || String(item.pid).includes(filter) || String(item.name).toLowerCase().includes(filter)).slice(0, 80);
    target.innerHTML = rows.map(item => `<div class="remote-row"><span><b>${escapeHtml(item.name)}</b><small>PID ${escapeHtml(item.pid)} · ${formatBytes(item.memory)}</small></span><button class="danger" data-pid="${escapeHtml(item.pid)}" type="button">Cerrar</button></div>`).join("") || '<span class="muted">No se encontraron procesos.</span>';
    target.querySelectorAll("[data-pid]").forEach(button => button.addEventListener("click", () => { if (confirm(`¿Cerrar ${button.previousElementSibling?.querySelector("b")?.textContent || "este proceso"}?`)) send("/api/processes/terminate", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({pid: Number(button.dataset.pid)})}).then(loadProcesses); }));
  } catch (error) { target.textContent = error.message; }
}

async function loadFiles(path = $("filePath").value.trim()) {
  const target = $("fileList"); target.textContent = "Cargando…";
  try {
    const data = await request(`/pc-files?path=${encodeURIComponent(path)}`);
    $("filePath").value = data.path;
    $("fileLocation").textContent = data.path;
    target.innerHTML = data.items.map(item => item.type === "directory" ? `<button class="file-row folder" data-path="${escapeHtml(item.path)}" type="button">📁 ${escapeHtml(item.name)}</button>` : `<div class="file-row"><span>📄 ${escapeHtml(item.name)}</span><button class="secondary" data-download="${escapeHtml(item.path)}" type="button">Descargar</button></div>`).join("") || '<span class="muted">Carpeta vacía.</span>';
    target.querySelectorAll("[data-path]").forEach(button => button.addEventListener("click", () => loadFiles(button.dataset.path)));
    target.querySelectorAll("[data-download]").forEach(button => button.addEventListener("click", () => downloadFile(button.dataset.download)));
  } catch (error) { target.textContent = error.message; }
}
async function downloadFile(path) {
  try { const response = await fetch(`${connection.endpoint}/pc-files/download?path=${encodeURIComponent(path)}`, {headers: headers()}); if (!response.ok) throw new Error("No se pudo descargar el archivo."); const blob = await response.blob(); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = path.split(/[\\/]/).pop() || "archivo"; link.click(); URL.revokeObjectURL(link.href); } catch (error) { notice(error.message); }
}
async function uploadFile(file) {
  if (!file) return; try { const body = new FormData(); body.append("file", file); const result = await request(`/pc-files/upload?path=${encodeURIComponent($("filePath").value)}`, {method: "POST", body}); notice(result.filename ? `Archivo subido: ${result.filename}` : "Archivo subido."); loadFiles(); } catch (error) { notice(error.message); }
}

function findBytes(buffer, first, start = 0) { for (let i = start; i < buffer.length; i++) if (buffer[i] === first[0] && buffer[i + 1] === first[1]) return i; return -1; }
async function startCamera() {
  if (!connection || cameraController) return;
  cameraController = new AbortController();
  $("startCamera").disabled = true; $("stopCamera").disabled = false; $("cameraEmpty").textContent = "Conectando con la cámara…";
  try {
    const response = await fetch(`${connection.endpoint}/camera`, {headers: headers(), signal: cameraController.signal});
    if (!response.ok || !response.body) throw new Error("No se pudo iniciar la cámara.");
    const reader = response.body.getReader(); let buffer = new Uint8Array(0);
    while (cameraController) {
      const part = await reader.read(); if (part.done) break;
      const merged = new Uint8Array(buffer.length + part.value.length); merged.set(buffer); merged.set(part.value, buffer.length); buffer = merged;
      let start = findBytes(buffer, [0xff, 0xd8]); let end = start < 0 ? -1 : findBytes(buffer, [0xff, 0xd9], start + 2);
      while (start >= 0 && end >= 0) {
        const frame = buffer.slice(start, end + 2); const blob = new Blob([frame], {type: "image/jpeg"});
        if (cameraObjectUrl) URL.revokeObjectURL(cameraObjectUrl); cameraObjectUrl = URL.createObjectURL(blob); $("camera").src = cameraObjectUrl; $("camera").hidden = false; $("cameraEmpty").hidden = true;
        buffer = buffer.slice(end + 2); start = findBytes(buffer, [0xff, 0xd8]); end = start < 0 ? -1 : findBytes(buffer, [0xff, 0xd9], start + 2);
      }
      if (buffer.length > 2_000_000) buffer = buffer.slice(-500_000);
    }
  } catch (error) { if (error.name !== "AbortError") notice(error.message); }
  finally { stopCamera(); }
}
function stopCamera() {
  if (cameraController) { cameraController.abort(); cameraController = null; }
  $("startCamera").disabled = false; $("stopCamera").disabled = true;
  if (!$('camera').src || $('camera').hidden) $('cameraEmpty').textContent = "La cámara está detenida.";
}

$("back").addEventListener("click", () => { location.href = "/pwa/"; });
$("refresh").addEventListener("click", refreshInfo);
$("sendText").addEventListener("click", () => { const text = $("text").value; if (text) send("/keyboard/text", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({text})}); });
document.querySelectorAll("[data-key]").forEach(button => button.addEventListener("click", () => send("/keyboard/key", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({key: button.dataset.key})})));
document.querySelectorAll("[data-action]").forEach(button => button.addEventListener("click", () => { const action = button.dataset.action; if (action === "shutdown" && !confirm("¿Apagar el PC?")) return; send(`/api/power/${action}`, {method: "POST"}); }));
$("logout").addEventListener("click", async () => { try { await request("/logout", {method: "POST"}); } catch (_) {} if (connection) { delete connection.token; connections.splice(index, 1); localStorage.setItem(STORAGE_KEY, JSON.stringify(connections)); } location.href = "/pwa/"; });
$("loadProcesses").addEventListener("click", loadProcesses);
$("processFilter").addEventListener("input", () => loadProcesses());
$("loadFiles").addEventListener("click", () => loadFiles());
$("uploadFile").addEventListener("change", event => uploadFile(event.target.files[0]));
$("startCamera").addEventListener("click", startCamera);
$("stopCamera").addEventListener("click", stopCamera);

if (!connection) { notice("No se encontró esta conexión. Vuelve a Mis PCs y agrégala de nuevo."); } else { refreshInfo(); setInterval(refreshScreen, 5000); }
