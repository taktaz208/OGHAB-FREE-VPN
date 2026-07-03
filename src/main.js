const invoke = window.__TAURI__.core.invoke;

const SOURCE_STORAGE_KEY = "oghab.sourceUrls";
const TUN_STORAGE_KEY = "oghab.tunMode";
const SUCCESS_HISTORY_KEY = "oghab.successHistory";
const DEFAULT_SOURCE_URLS = [
  "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/vless.txt",
  "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
];

const state = {
  profiles: [],
  selectedId: null,
  connectedUri: null,
  connectedTunnel: false,
  isScanning: false,
  isPaused: false,
  sourceUrls: loadSourceUrls(),
  tunnelMode: loadTunnelMode(),
  status: "Idle",
  snapshot: null,
  connecting: false,
};

const refreshBtn = document.querySelector("#refreshBtn");
const connectBtn = document.querySelector("#connectBtn");
const pauseBtn = document.querySelector("#pauseBtn");
const stopBtn = document.querySelector("#stopBtn");
const tunToggle = document.querySelector("#tunToggle");
const sourceInput = document.querySelector("#sourceInput");
const addSourceBtn = document.querySelector("#addSourceBtn");
const sourceList = document.querySelector("#sourceList");
const serverList = document.querySelector("#serverList");
const statusText = document.querySelector("#statusText");
const selectedText = document.querySelector("#selectedText");
const countText = document.querySelector("#countText");
const testedText = document.querySelector("#testedText");
const scanText = document.querySelector("#scanText");
const panelTitle = document.querySelector("#panelTitle");
const debugLog = document.querySelector("#debugLog");
const serversTabBtn = document.querySelector("#serversTabBtn");
const debugTabBtn = document.querySelector("#debugTabBtn");
const settingsTabBtn = document.querySelector("#settingsTabBtn");
const settingsPanel = document.querySelector("#settingsPanel");

let snapshotPollTimer = null;

refreshBtn.addEventListener("click", startScan);
connectBtn.addEventListener("click", toggleConnection);
pauseBtn.addEventListener("click", togglePause);
stopBtn.addEventListener("click", stopScan);
addSourceBtn.addEventListener("click", addSourceUrl);
tunToggle.addEventListener("change", toggleTunMode);
sourceInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    addSourceUrl();
  }
});
serversTabBtn.addEventListener("click", () => setPanelTab("servers"));
debugTabBtn.addEventListener("click", () => setPanelTab("debug"));
settingsTabBtn.addEventListener("click", () => setPanelTab("settings"));
window.addEventListener("beforeunload", () => invoke("disconnect_vpn").catch(() => { }));

init();

async function init() {
  renderSourceUrls();
  tunToggle.checked = state.tunnelMode;
  hydrateSuccessHistory();
  if (state.profiles.length) {
    updateStatus("History loaded");
  }
  await syncStatus();
  await syncSnapshot();
  startSnapshotPolling();
  if (!state.profiles.length && !hasSuccessHistory()) {
    await startScan();
  } else if (state.profiles.length) {
    renderProfiles();
    updateControls();
  }
}

async function syncStatus() {
  try {
    const status = await invoke("vpn_status");
    state.connectedUri = status.connected ? status.connected_uri : null;
    state.connectedTunnel = Boolean(status.tunnel_mode);
    updateStatus(status.connected ? (status.tunnel_mode ? "Connected TUN" : "Connected") : "Idle");
  } catch {
    updateStatus("Idle");
  }
  updateControls();
}

async function startScan() {
  try {
    state.isScanning = true;
    state.isPaused = false;
    updateStatus(state.connectedUri ? "Scanning" : "Scanning");
    const result = await invoke("start_scan", { sourceUrls: state.sourceUrls });
    applySnapshot(result);
    updateControls();
  } catch (error) {
    state.isScanning = false;
    updateStatus("Scan failed");
    scanText.textContent = "Failed";
    updateDebug([String(error)]);
    console.error(error);
  }
}

async function stopScan() {
  try {
    await invoke("stop_scan");
  } catch (error) {
    console.error(error);
  }
  state.isScanning = false;
  state.isPaused = false;
  updateControls();
}

async function togglePause() {
  if (!state.isScanning) {
    return;
  }

  try {
    if (state.isPaused) {
      await invoke("resume_scan");
      state.isPaused = false;
    } else {
      await invoke("pause_scan");
      state.isPaused = true;
    }
  } catch (error) {
    console.error(error);
  }

  updateControls();
}

async function toggleTunMode() {
  if (isAndroid()) {
    state.tunnelMode = true;
    tunToggle.checked = true;
    saveTunnelMode(true);
    updateControls();
    return;
  }

  state.tunnelMode = tunToggle.checked;
  saveTunnelMode(state.tunnelMode);
  updateControls();
}

async function toggleConnection() {
  const selected = getSelectedProfile();
  if (!selected) {
    return;
  }

  state.connecting = true;
  updateControls();

  try {
    if (state.connectedUri === selected.uri) {
      await invoke("disconnect_vpn");
      state.connectedUri = null;
      state.connectedTunnel = false;
      updateStatus("Disconnected");
    } else {
      await invoke("connect_profile", { uri: selected.uri, tunnelMode: state.tunnelMode });
      state.connectedUri = selected.uri;
      state.connectedTunnel = state.tunnelMode;
      saveSuccessProfile(selected);
      updateStatus(state.tunnelMode ? "Connected TUN" : "Connected");
    }
  } catch (error) {
    updateStatus("Connection failed");
    scanText.textContent = "Action failed";
    console.error(error);
  } finally {
    state.connecting = false;
    await syncStatus();
    updateControls();
  }
}

function updateStatus(text) {
  state.status = text;
  statusText.textContent = text;
}

function getSelectedProfile() {
  return state.profiles.find((profile) => profile.id === state.selectedId) ?? null;
}

function selectProfile(id) {
  state.selectedId = id;
  renderProfiles();
  updateControls();

  const selected = getSelectedProfile();
  if (state.connectedUri && selected && selected.uri !== state.connectedUri) {
    disconnectCurrentConnection();
  }
}

async function disconnectCurrentConnection() {
  try {
    await invoke("disconnect_vpn");
  } catch (error) {
    console.error(error);
  } finally {
    state.connectedUri = null;
    state.connectedTunnel = false;
    updateStatus("Disconnected");
    renderProfiles();
    updateControls();
  }
}

function renderProfiles() {
  const selected = getSelectedProfile();
  selectedText.textContent = selected ? selected.label : "None";

  if (!state.profiles.length) {
    serverList.innerHTML = `<div class="empty-state">No working VLESS servers are available yet.</div>`;
    return;
  }

  serverList.innerHTML = "";

  for (const profile of state.profiles) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "server-item";
    button.title = `${profile.label} | ${profile.host}:${profile.port}`;

    if (profile.id === state.selectedId) {
      button.classList.add("selected");
    }

    if (profile.uri === state.connectedUri) {
      button.classList.add("connected");
    }

    button.innerHTML = `
      <div class="server-main">
        <strong class="server-name">${escapeHtml(profile.label)}</strong>
        <span class="latency">${profile.latency_ms} ms</span>
      </div>
      <div class="server-host">${escapeHtml(profile.host)}:${profile.port} | ${escapeHtml(profile.network)} / ${escapeHtml(profile.security)}</div>
    `;
    button.addEventListener("click", () => selectProfile(profile.id));
    serverList.appendChild(button);
  }
}

function updateControls() {
  const selected = getSelectedProfile();
  const connected = selected && state.connectedUri === selected.uri;
  if (isAndroid()) {
    state.tunnelMode = true;
  }

  connectBtn.disabled = state.connecting || !selected;
  connectBtn.textContent = connected ? "Disconnect" : "Connect";
  refreshBtn.disabled = state.connecting;
  pauseBtn.disabled = !state.isScanning;
  pauseBtn.textContent = state.isPaused ? "Resume" : "Pause";
  stopBtn.disabled = !state.isScanning;
  tunToggle.checked = state.tunnelMode;
  tunToggle.disabled = isAndroid();

  if (state.isScanning) {
    scanText.textContent = state.isPaused
      ? `Paused ${state.snapshot?.scanned_count ?? 0}/${state.snapshot?.total_count ?? 0}`
      : `Scanning ${state.snapshot?.scanned_count ?? 0}/${state.snapshot?.total_count ?? 0}`;
  } else if (state.snapshot) {
    scanText.textContent = `${state.snapshot.working_count}/${state.snapshot.scanned_count ?? 0}`;
  }
}

function applySnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object") {
    return;
  }

  state.snapshot = snapshot;
  const nextProfiles = Array.isArray(snapshot.profiles) ? snapshot.profiles : [];
  if (nextProfiles.length) {
    state.profiles = nextProfiles;
  }
  state.isScanning = Boolean(snapshot.is_scanning);
  state.isPaused = Boolean(snapshot.is_paused);

  if (!state.profiles.some((profile) => profile.id === state.selectedId)) {
    state.selectedId = state.profiles[0]?.id ?? null;
  }

  countText.textContent = String(snapshot.working_count ?? state.profiles.length);
  testedText.textContent = `${snapshot.scanned_count ?? 0} / ${snapshot.total_count ?? 0}`;
  updateDebug(snapshot.lines ?? []);
  renderProfiles();
  renderSourceUrls();

  if (state.connectedUri) {
    updateStatus(state.connectedTunnel ? "Connected TUN" : "Connected");
  } else if (snapshot.error) {
    updateStatus(snapshot.error);
  } else if (state.isScanning) {
    updateStatus(state.isPaused ? "Scanning paused" : "Scanning");
  } else if (state.profiles.length) {
    updateStatus("Ready");
  } else {
    updateStatus("No working servers");
  }

  updateControls();
}

function renderSourceUrls() {
  sourceList.innerHTML = "";
  for (const url of state.sourceUrls) {
    const item = document.createElement("div");
    item.className = "source-item";
    item.title = url;
    item.innerHTML = `
      <span>${escapeHtml(shrinkText(url, 58))}</span>
      <button type="button" class="source-remove" aria-label="Remove source">x</button>
    `;
    item.querySelector(".source-remove").addEventListener("click", () => removeSourceUrl(url));
    sourceList.appendChild(item);
  }
}

function addSourceUrl() {
  const url = sourceInput.value.trim();
  if (!url) {
    return;
  }

  if (!state.sourceUrls.includes(url)) {
    state.sourceUrls = [...state.sourceUrls, url];
    saveSourceUrls(state.sourceUrls);
    renderSourceUrls();
  }

  sourceInput.value = "";
}

function removeSourceUrl(url) {
  state.sourceUrls = state.sourceUrls.filter((item) => item !== url);
  if (!state.sourceUrls.length) {
    state.sourceUrls = [...DEFAULT_SOURCE_URLS];
  }
  saveSourceUrls(state.sourceUrls);
  renderSourceUrls();
}

function setPanelTab(tab) {
  const debugActive = tab === "debug";
  const settingsActive = tab === "settings";
  serverList.classList.toggle("hidden", debugActive || settingsActive);
  debugLog.classList.toggle("hidden", !debugActive);
  settingsPanel.classList.toggle("hidden", !settingsActive);
  serversTabBtn.classList.toggle("active", !debugActive && !settingsActive);
  debugTabBtn.classList.toggle("active", debugActive);
  settingsTabBtn.classList.toggle("active", settingsActive);
  panelTitle.textContent = debugActive
    ? "Debug Log"
    : settingsActive
      ? "Settings"
      : "Working Servers";
}

function updateDebug(lines) {
  if (!Array.isArray(lines) || !lines.length) {
    debugLog.textContent = "No debug output yet.";
    return;
  }

  debugLog.textContent = lines.join("\n");
  debugLog.scrollTop = debugLog.scrollHeight;
}

function startSnapshotPolling() {
  stopSnapshotPolling();
  snapshotPollTimer = window.setInterval(syncSnapshot, 750);
}

function stopSnapshotPolling() {
  if (snapshotPollTimer !== null) {
    window.clearInterval(snapshotPollTimer);
    snapshotPollTimer = null;
  }
}

async function syncSnapshot() {
  try {
    const snapshot = await invoke("get_scan_snapshot");
    applySnapshot(snapshot);
  } catch (error) {
    console.error(error);
  }
}

function saveSourceUrls(sourceUrls) {
  window.localStorage.setItem(SOURCE_STORAGE_KEY, JSON.stringify(sourceUrls));
}

function loadSourceUrls() {
  try {
    const raw = window.localStorage.getItem(SOURCE_STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : null;
    if (Array.isArray(parsed) && parsed.length) {
      return parsed;
    }
  } catch {
    // Ignore malformed local state and fall back to defaults.
  }

  return [...DEFAULT_SOURCE_URLS];
}

function saveTunnelMode(enabled) {
  window.localStorage.setItem(TUN_STORAGE_KEY, enabled ? "1" : "0");
}

function loadTunnelMode() {
  const stored = window.localStorage.getItem(TUN_STORAGE_KEY);
  if (stored === null) {
    return isAndroid();
  }

  return isAndroid() || stored === "1";
}

function isAndroid() {
  return /Android/i.test(window.navigator.userAgent);
}

function hasSuccessHistory() {
  return loadSuccessHistory().length > 0;
}

function hydrateSuccessHistory() {
  const history = loadSuccessHistory();
  if (!history.length) {
    return;
  }

  state.profiles = history;
  state.selectedId = history[0].id;
}

function loadSuccessHistory() {
  try {
    const raw = window.localStorage.getItem(SUCCESS_HISTORY_KEY);
    const parsed = raw ? JSON.parse(raw) : null;
    if (Array.isArray(parsed)) {
      return parsed.filter((item) => item && typeof item === "object" && item.uri);
    }
  } catch {
    // Ignore malformed history and fall back to a blank state.
  }

  return [];
}

function saveSuccessProfile(profile) {
  const history = loadSuccessHistory().filter((item) => item.uri !== profile.uri);
  history.unshift({
    id: profile.id,
    uri: profile.uri,
    label: profile.label,
    host: profile.host,
    port: profile.port,
    latency_ms: profile.latency_ms,
    network: profile.network,
    security: profile.security,
  });

  window.localStorage.setItem(SUCCESS_HISTORY_KEY, JSON.stringify(history.slice(0, 10)));
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function shrinkText(value, limit) {
  if (value.length <= limit) {
    return value;
  }

  return `${value.slice(0, Math.max(0, limit - 3))}...`;
}
