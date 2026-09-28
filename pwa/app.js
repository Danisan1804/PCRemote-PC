const STORAGE_KEY = "pcremote.connections.v1";
const state = { connections: loadConnections() };
const $ = id => document.getElementById(id);

function loadConnections() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"); }
  catch (_) { return []; }
}

function saveConnections() { localStorage.setItem(STORAGE_KEY, JSON.stringify(state.connections)); }

function normalizeEndpoint(value) {
  let endpoint = value.trim().replace(/\/+$/, "");
  if (!/^https?:\/\//i.test(endpoint)) endpoint = `http://${endpoint}`;
  const url = new URL(endpoint);
  if (!url.hostname || (url.protocol !== "http:" && url.protocol !== "https:")) throw new Error("La dirección no es válida.");
  return url.origin;
}

async function request(connection, path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (connection.token) headers.set("Authorization", `Bearer ${connection.token}`);
  const response = await fetch(`${connection.endpoint}${path}`, {...options, headers, cache: "no-store"});
  const text = await response.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch (_) {}
  if (!response.ok) throw new Error(data.detail || data.error || `HTTP ${response.status}`);
  return data;
}

async function checkConnection(connection) {
  const response = await fetch(`${connection.endpoint}/api/instance/status`, {cache: "no-store"});
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
  return data;
}

function showNotice(message) { $("notice").hidden = !message; $("notice").textContent = message || ""; }

function showEndpointStatus(message, error = false) {
  const status = $("endpointStatus");
  status.className = `form-status${error ? " error" : " ok"}`;
  status.textContent = message;
}

async function checkFormEndpoint() {
  try {
    const endpoint = normalizeEndpoint($("endpoint").value);
    const data = await checkConnection({endpoint});
    const tail = data.tailscale?.connected ? "Tailscale conectado" : data.tailscale?.installed ? "Tailscale instalado, pero no conectado" : "Tailscale no detectado";
    showEndpointStatus(`${data.server === "online" ? "Servidor disponible" : "Servidor no disponible"} · ${data.configured ? "Instalación configurada" : "Falta crear la contraseña"} · ${tail}`, data.server !== "online" || !data.configured || !data.tailscale?.connected);
    return data;
  } catch (error) {
    showEndpointStatus(`No se pudo comprobar: ${error.message}`, true);
    throw error;
  }
}

function render() {
  const container = $("connections");
  if (!state.connections.length) {
    container.innerHTML = '<div class="empty">Todavía no hay computadores conectados.<br>Agrega el primero con el botón de arriba.</div>';
    return;
  }
  container.innerHTML = state.connections.map((connection, index) => `
    <article class="connection-card" data-index="${index}">
      <div><div class="connection-title">${escapeHtml(connection.name)}</div><div class="connection-endpoint">Conexión privada guardada en este dispositivo</div><div class="status" data-status>● Sin comprobar</div></div>
      <div class="card-actions"><button class="secondary" data-connect>Conectar</button><button class="danger" data-remove>Eliminar</button></div>
    </article>`).join("");
  container.querySelectorAll("[data-connect]").forEach(button => button.addEventListener("click", () => connect(Number(button.closest("article").dataset.index))));
  container.querySelectorAll("[data-remove]").forEach(button => button.addEventListener("click", () => removeConnection(Number(button.closest("article").dataset.index))));
  state.connections.forEach((_, index) => checkCard(index));
}

async function checkCard(index) {
  const card = document.querySelector(`[data-index="${index}"]`);
  if (!card) return;
  const status = card.querySelector("[data-status]");
  try {
    const data = await checkConnection(state.connections[index]);
    const tail = data.tailscale?.connected ? " · Tailscale conectado" : data.tailscale?.installed ? " · Tailscale sin conexión" : "";
    status.textContent = `● PC disponible${tail}`;
  } catch (_) { status.textContent = "● PC no disponible"; status.classList.add("offline"); }
}

async function connect(index) {
  const connection = state.connections[index];
  try {
    const data = await request(connection, "/api/system-info");
    showNotice(`${connection.name} conectado. Equipo: ${data.computer || "PC"}.`);
    window.location.href = `/pwa/control.html?pc=${encodeURIComponent(index)}`;
  } catch (error) {
    showNotice(`No se pudo conectar con ${connection.name}: ${error.message}`);
  }
}

async function removeConnection(index) {
  const connection = state.connections[index];
  try { if (connection.token) await request(connection, "/logout", {method: "POST"}); } catch (_) {}
  state.connections.splice(index, 1);
  saveConnections();
  render();
  showNotice("La conexión fue eliminada de este dispositivo.");
}

$("addButton").addEventListener("click", () => { $("connectPanel").hidden = false; $("displayName").focus(); });
$("closeButton").addEventListener("click", () => { $("connectPanel").hidden = true; });
$("checkButton").addEventListener("click", () => checkFormEndpoint().catch(() => {}));
$("connectForm").addEventListener("submit", async event => {
  event.preventDefault();
  const status = $("formStatus");
  status.className = "form-status";
  status.textContent = "Comprobando PC y contraseña...";
  try {
    const endpoint = normalizeEndpoint($("endpoint").value);
    const candidate = {name: $("displayName").value.trim(), endpoint, username: $("username").value.trim()};
    const instance = await checkFormEndpoint();
    const response = await fetch(`${endpoint}/login`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({username: candidate.username, password: $("password").value})});
    const data = await response.json();
    if (!response.ok || !data.success || !data.token) throw new Error(data.error || "Usuario o contraseña incorrectos.");
    candidate.token = data.token;
    candidate.instanceId = data.instance?.id || "";
    candidate.name = candidate.name || data.instance?.name || instance.display_name || "Mi PC";
    state.connections = state.connections.filter(item => item.endpoint !== endpoint);
    state.connections.push(candidate);
    saveConnections();
    $("connectForm").reset(); $("username").value = "admin"; $("connectPanel").hidden = true;
    render(); showNotice(`${candidate.name} quedó conectado.`);
  } catch (error) { status.className = "form-status error"; status.textContent = error.message; }
});

function escapeHtml(value) { return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;"); }

if ("serviceWorker" in navigator) window.addEventListener("load", () => navigator.serviceWorker.register("/pwa/sw.js").catch(() => {}));
render();
