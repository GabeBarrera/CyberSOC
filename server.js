#!/usr/bin/env node
/* ===================================================================
   CyberSOC — local server / proxy   (Node 18+, zero dependencies)

   Run:   node server.js
   Open:  http://localhost:3005

   Provides:
     GET  /api/health           -> liveness probe
     GET  /api/azure-status     -> live Azure region status (proxied)
     GET  /api/dossier          -> data/soc_dossier.json
     PUT  /api/dossier          -> overwrite data/soc_dossier.json (body = JSON array)
     GET  /api/geocode?q=...    -> Nominatim geocode (proxied, server-side)
     /*                         -> static files (index.html, data/, ...)
   =================================================================== */

const http = require("http");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

const PORT = 3005;
const ROOT = __dirname;
const DOSSIER_FILE = path.join(ROOT, "data", "soc_dossier.json");

/* Region catalogue — must mirror the codes used in index.html */
const REGIONS = [
  ["eastus", "East US"], ["eastus2", "East US 2"], ["centralus", "Central US"],
  ["northcentralus", "North Central US"], ["southcentralus", "South Central US"],
  ["westus", "West US"], ["westus2", "West US 2"], ["westus3", "West US 3"],
  ["canadacentral", "Canada Central"], ["canadaeast", "Canada East"], ["brazilsouth", "Brazil South"],
  ["northeurope", "North Europe"], ["westeurope", "West Europe"], ["uksouth", "UK South"],
  ["ukwest", "UK West"], ["francecentral", "France Central"], ["germanywc", "Germany West Central"],
  ["switzerlandn", "Switzerland North"], ["norwaye", "Norway East"], ["swedenc", "Sweden Central"],
  ["uaenorth", "UAE North"], ["southafrican", "South Africa North"], ["centralindia", "Central India"],
  ["southeastasia", "Southeast Asia"], ["eastasia", "East Asia"], ["japaneast", "Japan East"],
  ["koreacentral", "Korea Central"], ["australiaeast", "Australia East"]
];

const MIME = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
  ".png": "image/png", ".jpg": "image/jpeg", ".svg": "image/svg+xml", ".ico": "image/x-icon"
};

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}
function sendJSON(res, code, obj) {
  cors(res);
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(obj));
}

/* ---------- Azure status (best-effort proxy) ----------
   Scrapes the public Azure status RSS feed of active incidents and maps
   mentioned regions to degraded/outage. Everything else = operational.
   For production fidelity, swap this for the Azure Service Health API
   (Microsoft.ResourceHealth) using a token held here, server-side. */
const FEEDS = [
  "https://azure.status.microsoft/en-us/status/feed/",
  "https://status.azure.com/en-us/status/feed/"
];
function classify(text) {
  const t = text.toLowerCase();
  if (/(outage|unavailable|not available|is down|loss of|critical|major incident|impact to availability)/.test(t)) return "outage";
  if (/(degrad|elevated|latency|intermittent|investigating|mitigat|partial|warning|delays)/.test(t)) return "degraded";
  return null;
}
async function getAzureStatus() {
  if (typeof fetch !== "function") throw new Error("global fetch unavailable (need Node 18+)");
  let xml = null;
  for (const url of FEEDS) {
    try {
      const r = await fetch(url, { headers: { "User-Agent": "CyberSOC/1.0 (local SOC console)" } });
      if (r.ok) { xml = await r.text(); break; }
    } catch (e) { /* try next */ }
  }
  if (!xml) throw new Error("no feed reachable");

  // crude RSS item extraction
  const items = [];
  const re = /<item[\s\S]*?<\/item>/gi;
  let m;
  while ((m = re.exec(xml))) {
    const block = m[0];
    const title = (block.match(/<title>([\s\S]*?)<\/title>/i) || [])[1] || "";
    const desc = (block.match(/<description>([\s\S]*?)<\/description>/i) || [])[1] || "";
    items.push((title + " " + desc).replace(/<[^>]+>/g, " "));
  }

  const regions = REGIONS.map(([code, name]) => {
    let status = "operational", service = null, msg = null;
    for (const text of items) {
      if (text.toLowerCase().includes(name.toLowerCase())) {
        const sev = classify(text);
        if (sev) {
          if (sev === "outage" || status === "operational") {
            status = sev;
            msg = text.trim().slice(0, 180).replace(/\s+/g, " ");
          }
        }
      }
    }
    return { code, status, service, msg };
  });

  return { source: "azure-status-rss", fetchedAt: new Date().toISOString(), regions };
}

/* ---------- SolarWinds status (Atlassian Statuspage v2 API) ----------
   Clean JSON, no scraping. Maps Statuspage indicators to our 4 states. */
const SW_SUMMARY = "https://status.cloud.solarwinds.com/api/v2/summary.json";
const SW_MAP = {
  operational: "operational",
  degraded_performance: "degraded",
  partial_outage: "outage",
  major_outage: "outage",
  under_maintenance: "maintenance"
};
async function getSolarWindsStatus() {
  if (typeof fetch !== "function") throw new Error("global fetch unavailable (need Node 18+)");
  const r = await fetch(SW_SUMMARY, { headers: { "User-Agent": "CyberSOC/1.0 (local SOC console)", "Accept": "application/json" } });
  if (!r.ok) throw new Error("solarwinds http " + r.status);
  const j = await r.json();
  const comps = (j.components || [])
    .filter((c) => !c.group && c.name) // skip group containers
    .map((c) => ({ name: c.name, status: SW_MAP[c.status] || "operational" }));
  return { source: "solarwinds-statuspage", fetchedAt: new Date().toISOString(), components: comps };
}

/* ---------- dossier file ---------- */
function ensureDossierFile() {
  try {
    if (!fs.existsSync(DOSSIER_FILE)) {
      fs.mkdirSync(path.dirname(DOSSIER_FILE), { recursive: true });
      fs.writeFileSync(DOSSIER_FILE, "[]");
    }
  } catch (e) { console.error("dossier init:", e.message); }
}
function readDossier() {
  try { return JSON.parse(fs.readFileSync(DOSSIER_FILE, "utf8")); } catch (e) { return []; }
}
function writeDossier(list) {
  fs.writeFileSync(DOSSIER_FILE, JSON.stringify(list, null, 2));
}

/* ---------- geocode proxy ---------- */
async function geocode(q) {
  if (typeof fetch !== "function") throw new Error("need Node 18+");
  const url = "https://nominatim.openstreetmap.org/search?format=json&limit=1&q=" + encodeURIComponent(q);
  const r = await fetch(url, { headers: { "User-Agent": "CyberSOC/1.0 (local SOC console)", "Accept": "application/json" } });
  if (!r.ok) throw new Error("geocode http " + r.status);
  const a = await r.json();
  if (!a || !a[0]) return null;
  return { lat: +a[0].lat, lng: +a[0].lon, display: a[0].display_name };
}

/* ---------- static ---------- */
function serveStatic(req, res, pathname) {
  let rel = decodeURIComponent(pathname);
  if (rel === "/" || rel === "") rel = "/index.html";
  const filePath = path.normalize(path.join(ROOT, rel));
  if (!filePath.startsWith(ROOT)) { res.writeHead(403); return res.end("forbidden"); }
  fs.readFile(filePath, (err, buf) => {
    if (err) { res.writeHead(404); return res.end("not found"); }
    cors(res);
    res.writeHead(200, { "Content-Type": MIME[path.extname(filePath)] || "application/octet-stream" });
    res.end(buf);
  });
}

/* ---------- router ---------- */
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://localhost:" + PORT);
  const p = u.pathname;

  if (req.method === "OPTIONS") { cors(res); res.writeHead(204); return res.end(); }

  if (p === "/api/health") return sendJSON(res, 200, { ok: true, service: "CyberSOC", time: Date.now() });

  if (p === "/api/azure-status" && req.method === "GET") {
    try { return sendJSON(res, 200, await getAzureStatus()); }
    catch (e) { return sendJSON(res, 502, { error: "azure feed unavailable", detail: e.message }); }
  }

  if (p === "/api/solarwinds-status" && req.method === "GET") {
    try { return sendJSON(res, 200, await getSolarWindsStatus()); }
    catch (e) { return sendJSON(res, 502, { error: "solarwinds feed unavailable", detail: e.message }); }
  }

  if (p === "/api/dossier" && req.method === "GET") {
    ensureDossierFile();
    return sendJSON(res, 200, readDossier());
  }
  if (p === "/api/dossier" && req.method === "PUT") {
    let body = "";
    req.on("data", (c) => { body += c; if (body.length > 8e6) req.destroy(); });
    req.on("end", () => {
      try {
        const list = JSON.parse(body);
        if (!Array.isArray(list)) throw new Error("expected an array");
        writeDossier(list);
        sendJSON(res, 200, { ok: true, count: list.length });
      } catch (e) { sendJSON(res, 400, { error: e.message }); }
    });
    return;
  }

  if (p === "/api/geocode" && req.method === "GET") {
    const q = u.searchParams.get("q");
    if (!q) return sendJSON(res, 400, { error: "missing q" });
    try {
      const g = await geocode(q);
      if (!g) return sendJSON(res, 404, { error: "not found" });
      return sendJSON(res, 200, g);
    } catch (e) { return sendJSON(res, 502, { error: e.message }); }
  }

  return serveStatic(req, res, p);
});

ensureDossierFile();
server.listen(PORT, () => {
  console.log("\n  ◆ CyberSOC server running");
  console.log("  → http://localhost:" + PORT + "\n");
  console.log("  Azure feed : GET  /api/azure-status");
  console.log("  SolarWinds : GET  /api/solarwinds-status");
  console.log("  Dossier    : GET/PUT /api/dossier  (writes data/soc_dossier.json)");
  console.log("  Geocode    : GET  /api/geocode?q=<address>\n");
});
