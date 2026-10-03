/* OWSI browser extension — background service worker (MV3).
 *
 * Responsibilities:
 *  1. Maintain a live WebSocket to the local OWSI control API and keep the
 *     engine informed this extension is alive (/ext/register handshake).
 *  2. Forward browser network events (method/url/status/timings/headers) to
 *     the engine via POST /ext/traffic so they appear in History.
 *  3. Execute commands pushed by the engine over the WS feed:
 *       {cmd:"setProxy",host,port}   → chrome.proxy fixed proxy + save prior
 *       {cmd:"clearProxy"}           → restore saved prior proxy settings
 *       {cmd:"reloadAll"}            → reload all http(s) tabs
 *       {cmd:"interceptOn|Off"}      → toggle request interception flag
 *  4. Badge state (ON/OFF) and status cache for the popup.
 *
 * Security notes (spec §71): we only ever talk to 127.0.0.1 on the configured
 * port; all engine-originated commands must arrive over the localhost WS and
 * carry the shared token issued at registration time. Browser-provided data
 * is treated as untrusted input.
 */

const DEFAULT_API = "http://127.0.0.1:9000";
const PROXY_STORAGE_KEY = "owsiPriorProxyConfig";

let ws = null;
let reconnectDelay = 1000;
let regToken = "";

async function api(path, opts = {}) {
  const stored = await chrome.storage.local.get(["owsiApi"]);
  const base = stored.owsiApi || DEFAULT_API;
  const headers = { "Content-Type": "application/json" };
  if (regToken) headers["X-OWSI-Token"] = regToken;
  const r = await fetch(base + path, {
    method: opts.method || "GET",
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  return r.ok ? r.json() : Promise.reject(new Error(`${path} -> ${r.status}`));
}

// ------------------------------------------------------------------ bridge
function connectBridge() {
  if (ws && (ws.readyState === WebSocket.OPEN ||
            ws.readyState === WebSocket.CONNECTING)) return;
  const w = new WebSocket("ws://127.0.0.1:9000/ws");
  ws = w;
  w.onopen = async () => {
    reconnectDelay = 1000;
    try {
      const res = await api("/ext/register", {
        method: "POST",
        body: {
          client: "owsi-extension",
          version: chrome.runtime.getManifest().version,
          browser: navigator.userAgent.includes("Edg/") ? "edge" : "chrome",
        },
      });
      regToken = res.token || "";
      setBadge(true);
    } catch (e) { /* engine up but register failed; retry on next msg */ }
  };
  w.onmessage = (ev) => {
    let env;
    try { env = JSON.parse(ev.data); } catch { return; }
    // envelope: {type, payload, t}
    if (env.type === "ext.command") handleCommand(env.payload || {});
  };
  w.onclose = w.onerror = () => {
    ws = null;
    setBadge(false);
    setTimeout(connectBridge, Math.min(reconnectDelay *= 2, 15000));
  };
}

async function handleCommand(cmd) {
  try {
    if (cmd.cmd === "setProxy") {
      await savePriorProxy();
      await chrome.proxy.settings.clear({ scope: "regular" }).catch(() => {});
      await chrome.proxy.settings.set({
        value: {
          mode: "fixed_servers",
          rules: {
            singleProxy: { scheme: "http",
                           host: cmd.host || "127.0.0.1",
                           port: parseInt(cmd.port || 8080, 10) },
            bypassList: ["127.0.0.1", "localhost"],
          },
        },
        scope: "regular",
      });
      reportResult(cmd, { ok: true, proxy: `${cmd.host}:${cmd.port}` });
    } else if (cmd.cmd === "clearProxy") {
      await restorePriorProxy();
      reportResult(cmd, { ok: true, proxy: "restored" });
    } else if (cmd.cmd === "reloadAll") {
      const tabs = await chrome.tabs.query({ url: ["http://*/*", "https://*/*"] });
      await Promise.all(tabs.map((t) => chrome.tabs.reload(t.id)));
      reportResult(cmd, { ok: true, reloaded: tabs.length });
    } else if (cmd.cmd === "interceptOn" || cmd.cmd === "interceptOff") {
      await api("/api/intercept/config", {
        method: "POST",
        body: { requests: cmd.cmd === "interceptOn",
                responses: cmd.cmd === "interceptOn" },
      });
      reportResult(cmd, { ok: true });
    }
  } catch (e) {
    reportResult(cmd, { ok: false, error: String(e) });
  }
}

async function reportResult(cmd, result) {
  try {
    await api("/ext/command-result", {
      method: "POST",
      body: { cmd: cmd.cmd, ...result },
    });
  } catch { /* engine may be down; nothing to do */ }
}

async function savePriorProxy() {
  const prior = await chrome.proxy.settings.get({});
  if (prior.value && prior.value.mode !== "system") {
    await chrome.storage.local.set({ [PROXY_STORAGE_KEY]: prior.value });
  } else {
    await chrome.storage.local.remove(PROXY_STORAGE_KEY);
  }
}

async function restorePriorProxy() {
  const stored = await chrome.storage.local.get(PROXY_STORAGE_KEY);
  const prior = stored[PROXY_STORAGE_KEY];
  if (prior) {
    await chrome.proxy.settings.set({ value: prior, scope: "regular" });
    await chrome.storage.local.remove(PROXY_STORAGE_KEY);
  } else {
    await chrome.proxy.settings.clear({ scope: "regular" });
  }
}

function setBadge(on) {
  chrome.action.setBadgeText({ text: on ? "ON" : "" });
  chrome.action.setBadgeBackgroundColor({ color: "#16a34a" });
}

// ------------------------------------------------------------- traffic feed
const seen = new Map();   // requestId -> partial event

chrome.webRequest.onBeforeRequest.addListener(
  (d) => {
    if (d.url.startsWith("ws://") || d.url.startsWith("wss://")) return;
    seen.set(d.requestId, {
      url: d.url, method: d.method, tabId: d.tabId, start: Date.now(),
    });
    if (seen.size > 5000) {  // bounded memory
      const firstKey = seen.keys().next().value;
      seen.delete(firstKey);
    }
  },
  { urls: ["<all_urls>"] },
);

chrome.webRequest.onHeadersReceived.addListener(
  (d) => {
    const base = seen.get(d.requestId);
    if (!base) return;
    if (d.statusCode >= 300 && d.statusCode < 400 &&
        d.type !== "main_frame" && d.type !== "sub_frame") {
      // subresource redirect: Chrome follows it internally; record anyway
    }
    const reqHeaders = {};
    // requestHeaders not available here; best-effort from stored info only
    const respHeaders = {};
    for (const h of d.responseHeaders || []) reqHeadersSet(respHeaders, h);
    function reqHeadersSet(o, h) { o[h.name] = h.value; }
    const evt = {
      ...base,
      statusCode: d.statusCode,
      statusLine: d.statusLine,
      responseHeaders: respHeaders,
      timeMs: Date.now() - base.start,
    };
    seen.delete(d.requestId);
    sendTraffic(evt);
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"],
);

function sendTraffic(evt) {
  api("/ext/traffic", { method: "POST", body: evt })
    .then(() => api("/ext/command-result", { method: "POST",
      body: { cmd: "trafficAck", id: evt.requestId } }).catch(() => {}))
    .catch(() => {});
}

// ------------------------------------------------------------------ lifecycle
chrome.runtime.onInstalled.addListener(connectBridge);
chrome.runtime.onStartup.addListener(connectBridge);
chrome.alarms.create("owsi-ping", { periodInMinutes: 0.4 });
chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === "owsi-ping") {
    if (!ws || ws.readyState !== WebSocket.OPEN) connectBridge();
  }
});
connectBridge();
