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
     POST /api/exec             -> run a shell command on the host  ⚠ LOCAL USE ONLY
     /*                         -> static files (index.html, data/, ...)
   =================================================================== */

const http = require("http");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");
const { exec } = require("child_process");

const PORT = 3005;
const ROOT = __dirname;
const DOSSIER_FILE = path.join(ROOT, "data", "soc_dossier.json");
const FILES_FILE = path.join(ROOT, "data", "soc_files.json");
const IMG_DIR = path.join(ROOT, "assets", "images");

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
  ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
  ".webp": "image/webp", ".bmp": "image/bmp", ".svg": "image/svg+xml", ".ico": "image/x-icon"
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

/* ===================================================================
   THREAT INTELLIGENCE — public infosec feeds (no API keys required)
   Sources:
     • CISA KEV   — actively-exploited CVEs (Known Exploited Vulns)
     • Feodo Tracker (abuse.ch) — botnet C2 / malicious IPs  [HAS GEO]
     • ThreatFox  (abuse.ch)    — recent IOCs (C2, payloads, domains)
   All are refreshed in the background on a timer (see startup) and
   served instantly from THREAT_INTEL cache via /api/threat-intel.
   Items are normalized to a single shape the client renders directly:
     { id, cat, sev, title, sub, msg, ts, src, lat?, lng?, geo? }
   =================================================================== */

/* ISO-3166 alpha-2 → approximate country centroid [lat, lng].
   Used to plot C2 / malicious IPs (which carry a country code, not a
   precise location) onto the SITREP map. */
const COUNTRY_CENTROIDS = {
  US:[39.8,-98.6], CA:[56.1,-106.3], MX:[23.6,-102.6], BR:[-14.2,-51.9], AR:[-38.4,-63.6],
  CL:[-35.7,-71.5], CO:[4.6,-74.3], PE:[-9.2,-75.0], VE:[6.4,-66.6], EC:[-1.8,-78.2],
  GB:[55.4,-3.4], IE:[53.4,-8.2], FR:[46.2,2.2], DE:[51.2,10.4], NL:[52.1,5.3],
  BE:[50.5,4.5], LU:[49.8,6.1], CH:[46.8,8.2], AT:[47.5,14.6], IT:[41.9,12.6],
  ES:[40.5,-3.7], PT:[39.4,-8.2], SE:[60.1,18.6], NO:[60.5,8.5], FI:[61.9,25.7],
  DK:[56.3,9.5], PL:[51.9,19.1], CZ:[49.8,15.5], SK:[48.7,19.7], HU:[47.2,19.5],
  RO:[45.9,24.97], BG:[42.7,25.5], GR:[39.1,21.8], RS:[44.0,21.0], HR:[45.1,15.2],
  UA:[48.4,31.2], RU:[61.5,105.3], BY:[53.7,27.9], LT:[55.2,23.9], LV:[56.9,24.6],
  EE:[58.6,25.0], MD:[47.4,28.4], TR:[39.0,35.2], IL:[31.0,34.9], SA:[23.9,45.1],
  AE:[23.4,53.8], QA:[25.3,51.2], KW:[29.3,47.5], IR:[32.4,53.7], IQ:[33.2,43.7],
  EG:[26.8,30.8], ZA:[-30.6,22.9], NG:[9.1,8.7], KE:[-0.0,37.9], MA:[31.8,-7.1],
  DZ:[28.0,1.7], TN:[33.9,9.6], GH:[7.9,-1.0], ET:[9.1,40.5], TZ:[-6.4,34.9],
  IN:[20.6,79.0], PK:[30.4,69.3], BD:[23.7,90.4], LK:[7.9,80.8], NP:[28.4,84.1],
  CN:[35.9,104.2], HK:[22.4,114.1], TW:[23.7,121.0], JP:[36.2,138.3], KR:[35.9,127.8],
  KP:[40.3,127.5], VN:[14.1,108.3], TH:[15.9,100.99], MY:[4.2,101.98], SG:[1.35,103.82],
  ID:[-0.8,113.9], PH:[12.9,121.8], MM:[21.9,95.96], KH:[12.6,104.99], LA:[19.9,102.5],
  AU:[-25.7,133.8], NZ:[-41.8,174.9], FJ:[-17.7,178.1], KZ:[48.0,66.9], UZ:[41.4,64.6],
  AZ:[40.1,47.6], GE:[42.3,43.4], AM:[40.1,45.0], MN:[46.9,103.8], PA:[8.5,-80.8],
  CR:[9.7,-83.8], GT:[15.8,-90.2], DO:[18.7,-70.2], JM:[18.1,-77.3], CU:[21.5,-77.8],
  PR:[18.2,-66.5], IS:[64.96,-19.0], CY:[35.1,33.4], MT:[35.9,14.4], SI:[46.2,15.0],
  AL:[41.2,20.2], MK:[41.6,21.7], BA:[43.9,17.7], ME:[42.7,19.4], LB:[33.9,35.9],
  JO:[31.3,36.2], SY:[34.8,38.99], YE:[15.6,48.0], OM:[21.5,55.9], BH:[26.0,50.6],
  AO:[-11.2,17.9], MZ:[-18.7,35.5], ZM:[-13.1,27.8], ZW:[-19.0,29.9], UG:[1.4,32.3],
  SN:[14.5,-14.5], CI:[7.5,-5.5], CM:[7.4,12.4], CD:[-4.0,21.8], SD:[12.9,30.2]
};
function geoForCountry(cc) {
  if (!cc) return null;
  const c = COUNTRY_CENTROIDS[String(cc).toUpperCase()];
  if (!c) return null;
  // small deterministic jitter so multiple IPs in one country fan out
  const j = (s) => { let h = 0; for (const ch of String(s)) h = (h * 31 + ch.charCodeAt(0)) & 0xffff; return ((h % 1000) / 1000 - 0.5) * 6; };
  return { lat: c[0] + j(cc + "lat"), lng: c[1] + j(cc + "lng") };
}

async function fetchJSON(url, opts) {
  if (typeof fetch !== "function") throw new Error("global fetch unavailable (need Node 18+)");
  const r = await fetch(url, Object.assign({
    headers: { "User-Agent": "CyberSOC/1.0 (local SOC console)", "Accept": "application/json" }
  }, opts || {}));
  if (!r.ok) throw new Error("http " + r.status);
  return r.json();
}

/* ---- CISA Known Exploited Vulnerabilities ---- */
const CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
async function getCISA() {
  const j = await fetchJSON(CISA_KEV);
  const vulns = (j.vulnerabilities || [])
    .slice()
    .sort((a, b) => (b.dateAdded || "").localeCompare(a.dateAdded || ""))
    .slice(0, 14);
  return vulns.map((v) => ({
    id: "kev-" + v.cveID,
    cat: "CVE",
    sev: v.knownRansomwareCampaignUse === "Known" ? "outage" : "degraded",
    title: v.cveID,
    sub: [v.vendorProject, v.product].filter(Boolean).join(" "),
    msg: v.vulnerabilityName + (v.shortDescription ? " — " + v.shortDescription : ""),
    ts: v.dateAdded ? new Date(v.dateAdded + "T00:00:00Z").getTime() : Date.now(),
    ransomware: v.knownRansomwareCampaignUse === "Known",
    src: "CISA KEV"
  }));
}

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
function tsFromSpace(s) { return s ? new Date(String(s).replace(" ", "T") + "Z").getTime() : Date.now(); }

/* ---- Feodo Tracker — botnet C2 / malicious IPs (carries country) ---- */
const FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";
async function getFeodo() {
  const arr = await fetchJSON(FEODO);
  const rows = (Array.isArray(arr) ? arr : [])
    .slice()
    .sort((a, b) => (a.status === "online" ? -1 : 1) - (b.status === "online" ? -1 : 1))
    .slice(0, 45);
  return rows.map((r) => ({
    id: "c2-" + r.ip_address + ":" + (r.port || 0),
    cat: "C2",
    sev: r.status === "online" ? "outage" : "degraded",
    title: r.ip_address + (r.port ? ":" + r.port : ""),
    sub: (r.malware || "Botnet C2") + (r.country ? " · " + r.country : ""),
    msg: [r.malware ? r.malware + " command-and-control node" : "Botnet C2 node",
          r.status ? "(" + r.status + ")" : "", r.as_name ? "AS: " + r.as_name : ""]
          .filter(Boolean).join(" "),
    ts: r.last_online ? tsFromSpace(r.last_online) : (r.first_seen ? tsFromSpace(r.first_seen) : Date.now()),
    src: "Feodo Tracker",
    ip: r.ip_address,            // precise geo via ip-api
    cc: r.country || undefined   // country-centroid fallback
  }));
}

/* ---- ThreatFox — recent IOCs (abuse.ch) ---- */
const THREATFOX = "https://threatfox.abuse.ch/export/json/recent/";
async function getThreatFox() {
  const j = await fetchJSON(THREATFOX);
  const out = [];
  for (const key of Object.keys(j || {})) {
    const rec = Array.isArray(j[key]) ? j[key][0] : j[key];
    if (!rec || !rec.ioc_value) continue;
    const ipPart = String(rec.ioc_value).split(":")[0];
    out.push({
      id: "iocfx-" + key,
      cat: "IOC",
      sev: (rec.confidence_level || 0) >= 75 ? "outage" : "degraded",
      title: String(rec.ioc_value).slice(0, 46),
      sub: (rec.malware_printable || rec.threat_type || "IOC") +
           (rec.ioc_type ? " · " + rec.ioc_type : ""),
      msg: [rec.threat_type_desc || rec.threat_type || "",
            rec.confidence_level != null ? "confidence " + rec.confidence_level + "%" : "",
            (rec.tags && rec.tags.length) ? "tags: " + rec.tags.slice(0, 4).join(", ") : ""]
            .filter(Boolean).join(" · "),
      ts: rec.first_seen_utc ? tsFromSpace(rec.first_seen_utc) : Date.now(),
      src: "ThreatFox",
      ip: IPV4.test(ipPart) ? ipPart : undefined
    });
    if (out.length >= 30) break;
  }
  return out;
}

/* ---- URLhaus — recent malicious URLs (abuse.ch) ---- */
const URLHAUS = "https://urlhaus.abuse.ch/downloads/json_recent/";
async function getURLhaus() {
  const j = await fetchJSON(URLHAUS);
  const out = [];
  for (const key of Object.keys(j || {})) {
    const rec = Array.isArray(j[key]) ? j[key][0] : j[key];
    if (!rec || !rec.url) continue;
    out.push({
      id: "url-" + key,
      cat: "URL",
      sev: rec.url_status === "online" ? "outage" : "degraded",
      title: (rec.host || rec.url || "").slice(0, 46),
      sub: (rec.threat || "malware URL").replace(/_/g, " ") + (rec.url_status ? " · " + rec.url_status : ""),
      msg: [String(rec.url).slice(0, 90),
            (rec.tags && rec.tags.length) ? "tags: " + rec.tags.slice(0, 4).join(", ") : ""]
            .filter(Boolean).join(" · "),
      ts: rec.date_added ? tsFromSpace(rec.date_added.replace(" UTC", "")) : Date.now(),
      src: "URLhaus",
      ip: rec.host && IPV4.test(rec.host) ? rec.host : undefined
    });
    if (out.length >= 30) break;
  }
  return out;
}

/* ---- Tor Project — running exit relays (Onionoo, carries lat/lng) ---- */
const ONIONOO = "https://onionoo.torproject.org/details?type=relay&running=true&flag=Exit&fields=nickname,country,country_name,latitude,longitude,as_name";
async function getTor() {
  const j = await fetchJSON(ONIONOO);
  const relays = (j.relays || []).filter((r) => r.latitude != null && r.longitude != null).slice(0, 90);
  return relays.map((r, i) => ({
    id: "tor-" + (r.nickname || i) + "-" + i,
    cat: "TOR",
    sev: "info",
    title: r.nickname || "exit relay",
    sub: "Tor exit · " + (r.country_name || (r.country || "").toUpperCase()),
    msg: ["Tor exit relay", r.as_name ? "AS: " + r.as_name : ""].filter(Boolean).join(" · "),
    ts: Date.now(),
    src: "Tor Project",
    lat: +r.latitude,
    lng: +r.longitude,
    geo: (r.country || "").toUpperCase() || undefined
  }));
}

/* ---- ransomware.live — recent ransomware victim disclosures ---- */
const RANSOMWARE = "https://api.ransomware.live/recentvictims";
async function getRansomware() {
  const arr = await fetchJSON(RANSOMWARE);
  const rows = (Array.isArray(arr) ? arr : []).slice(0, 30);
  return rows.map((r, i) => ({
    id: "ransom-" + (r.post_title || i) + "-" + (r.discovered || i),
    cat: "RANSOM",
    sev: "outage",
    title: (r.post_title || "victim").slice(0, 46),
    sub: (r.group_name ? r.group_name.toUpperCase() : "Ransomware") + (r.country ? " · " + r.country : ""),
    msg: ["Ransomware victim disclosure",
          r.group_name ? "group: " + r.group_name : "",
          r.activity ? "sector: " + r.activity : ""].filter(Boolean).join(" · "),
    ts: r.discovered ? tsFromSpace(r.discovered) : (r.published ? Date.parse(r.published) || Date.now() : Date.now()),
    src: "ransomware.live",
    cc: r.country || undefined
  }));
}

/* ---- precise geolocation of IP-bearing items via ip-api.com (free, no key,
   HTTP-only, batch up to 100/req) — then country-centroid fallback. ---- */
async function geoEnrich(items) {
  const need = items.filter((it) => it.ip && it.lat == null);
  const ips = [...new Set(need.map((it) => it.ip))].slice(0, 100);
  const map = {};
  if (ips.length) {
    try {
      const r = await fetch("http://ip-api.com/batch?fields=status,countryCode,city,lat,lon,query", {
        method: "POST",
        headers: { "User-Agent": "CyberSOC/1.0 (local SOC console)", "Content-Type": "application/json" },
        body: JSON.stringify(ips)
      });
      if (r.ok) {
        const arr = await r.json();
        (Array.isArray(arr) ? arr : []).forEach((o) => {
          if (o && o.status === "success") map[o.query] = { lat: o.lat, lng: o.lon, cc: o.countryCode, city: o.city };
        });
      }
    } catch (e) { /* offline / blocked — fall through to centroids */ }
  }
  let precise = 0, centroid = 0;
  items.forEach((it) => {
    if (it.lat != null) return;
    if (it.ip && map[it.ip]) {
      const g = map[it.ip];
      it.lat = g.lat; it.lng = g.lng; it.geo = it.geo || g.cc; it.city = g.city; precise++;
    } else if (it.cc) {
      const g = geoForCountry(it.cc);
      if (g) { it.lat = g.lat; it.lng = g.lng; it.geo = it.geo || it.cc; centroid++; }
    }
  });
  return { precise, centroid };
}

/* In-memory cache + background refresher (every 60s; see startup). */
const THREAT_INTEL = { fetchedAt: null, feeds: {}, items: [] };
let _refreshing = false;
async function refreshThreatIntel() {
  if (_refreshing) return THREAT_INTEL;
  _refreshing = true;
  const jobs = [
    ["cisa", getCISA], ["feodo", getFeodo], ["threatfox", getThreatFox],
    ["urlhaus", getURLhaus], ["tor", getTor], ["ransomware", getRansomware]
  ];
  const results = await Promise.allSettled(jobs.map(([, fn]) => fn()));
  const items = [];
  const feeds = {};
  results.forEach((res, i) => {
    const name = jobs[i][0];
    if (res.status === "fulfilled") {
      feeds[name] = { ok: true, count: res.value.length };
      items.push(...res.value);
    } else {
      feeds[name] = { ok: false, error: (res.reason && res.reason.message) || "failed" };
    }
  });
  const geo = await geoEnrich(items);
  items.sort((a, b) => (b.ts || 0) - (a.ts || 0));
  THREAT_INTEL.fetchedAt = new Date().toISOString();
  THREAT_INTEL.feeds = feeds;
  THREAT_INTEL.items = items;
  THREAT_INTEL.geo = geo;
  _refreshing = false;
  const live = Object.values(feeds).filter((f) => f.ok).length;
  console.log(`  ◇ threat-intel refreshed @ ${THREAT_INTEL.fetchedAt} · ${items.length} items · ${live}/${jobs.length} feeds live · geo ${geo.precise}+${geo.centroid}`);
  return THREAT_INTEL;
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

/* ---------- log documentation file (soc_files.json) ---------- */
function ensureFilesFile() {
  try {
    if (!fs.existsSync(FILES_FILE)) {
      fs.mkdirSync(path.dirname(FILES_FILE), { recursive: true });
      fs.writeFileSync(FILES_FILE, "[]");
    }
  } catch (e) { console.error("files init:", e.message); }
}
function readFiles() {
  try { return JSON.parse(fs.readFileSync(FILES_FILE, "utf8")); } catch (e) { return []; }
}
function writeFiles(list) {
  fs.writeFileSync(FILES_FILE, JSON.stringify(list, null, 2));
}

/* ---------- dossier photo storage (assets/images/) ----------
   Persists an uploaded image to disk and returns its relative path so
   the dossier stores a file location instead of a fat base64 blob. */
function ensureImgDir() {
  try { if (!fs.existsSync(IMG_DIR)) fs.mkdirSync(IMG_DIR, { recursive: true }); }
  catch (e) { console.error("img dir init:", e.message); }
}
const IMG_EXT = {
  "image/png": "png", "image/jpeg": "jpg", "image/jpg": "jpg", "image/gif": "gif",
  "image/webp": "webp", "image/bmp": "bmp", "image/svg+xml": "svg"
};
function saveUploadedImage(filename, dataUrl) {
  const m = /^data:(image\/[a-zA-Z0-9.+-]+);base64,([\s\S]*)$/.exec(dataUrl || "");
  if (!m) throw new Error("expected a base64 image data URL");
  const ext = IMG_EXT[m[1].toLowerCase()] || "png";
  const base = String(filename || "subject").toLowerCase()
    .replace(/\.[a-z0-9]+$/, "").replace(/[^a-z0-9._-]/g, "-").replace(/-+/g, "-").slice(0, 40) || "subject";
  const name = base + "-" + Date.now() + "." + ext;
  ensureImgDir();
  fs.writeFileSync(path.join(IMG_DIR, name), Buffer.from(m[2], "base64"));
  return "assets/images/" + name;
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

  /* Threat-intel cache — served instantly; refreshed in the background.
     ?refresh=1 forces an immediate re-pull before responding. */
  if (p === "/api/threat-intel" && req.method === "GET") {
    try {
      if (u.searchParams.get("refresh") === "1" || !THREAT_INTEL.fetchedAt) await refreshThreatIntel();
      return sendJSON(res, 200, THREAT_INTEL);
    } catch (e) { return sendJSON(res, 502, { error: "threat intel unavailable", detail: e.message }); }
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

  /* ---------- dossier photo upload (writes assets/images/<file>) ---------- */
  if (p === "/api/upload-image" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => { body += c; if (body.length > 2e7) req.destroy(); });
    req.on("end", () => {
      try {
        const { filename, dataUrl } = JSON.parse(body);
        const rel = saveUploadedImage(filename, dataUrl);
        sendJSON(res, 200, { ok: true, path: rel });
      } catch (e) { sendJSON(res, 400, { error: e.message }); }
    });
    return;
  }

  /* ---------- log documentation repository (data/soc_files.json) ---------- */
  if (p === "/api/files" && req.method === "GET") {
    ensureFilesFile();
    return sendJSON(res, 200, readFiles());
  }
  if (p === "/api/files" && req.method === "PUT") {
    let body = "";
    req.on("data", (c) => { body += c; if (body.length > 5e7) req.destroy(); });
    req.on("end", () => {
      try {
        const list = JSON.parse(body);
        if (!Array.isArray(list)) throw new Error("expected an array");
        writeFiles(list);
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

  /* ---------- localhost shell bridge ----------
     Runs an arbitrary command on the host machine and returns its output.
     ⚠ This is a remote-code-execution endpoint. The server binds to
     127.0.0.1 only (see server.listen below) so it is not reachable from
     the network. Do NOT expose this server publicly or change the bind. */
  if (p === "/api/exec" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on("end", () => {
      let cmd;
      try { cmd = JSON.parse(body).cmd; } catch (e) { return sendJSON(res, 400, { error: "invalid JSON body" }); }
      if (!cmd || typeof cmd !== "string") return sendJSON(res, 400, { error: "missing 'cmd' string" });
      exec(cmd, { cwd: ROOT, timeout: 15000, maxBuffer: 4e6, windowsHide: true }, (err, stdout, stderr) => {
        sendJSON(res, 200, {
          cmd,
          stdout: stdout || "",
          stderr: stderr || (err && err.code === undefined ? String(err.message) : ""),
          code: err ? (typeof err.code === "number" ? err.code : 1) : 0
        });
      });
    });
    return;
  }

  return serveStatic(req, res, p);
});

ensureDossierFile();
ensureFilesFile();
ensureImgDir();

/* Refresh every public infosec feed in the background once per minute so
   the page can pick up new CVEs / C2s / IOCs without a manual reload. */
refreshThreatIntel().catch((e) => console.error("threat-intel init:", e.message));
setInterval(() => refreshThreatIntel().catch((e) => console.error("threat-intel refresh:", e.message)), 60000);

server.listen(PORT, "127.0.0.1", () => {
  console.log("\n  ◆ CyberSOC server running");
  console.log("  → http://localhost:" + PORT + "  (loopback only)\n");
  console.log("  Azure feed : GET  /api/azure-status");
  console.log("  SolarWinds : GET  /api/solarwinds-status");
  console.log("  ThreatIntel: GET  /api/threat-intel   (CISA KEV · Feodo C2 · ThreatFox · auto-refresh 60s)");
  console.log("  Dossier    : GET/PUT /api/dossier  (writes data/soc_dossier.json)");
  console.log("  Log files  : GET/PUT /api/files    (writes data/soc_files.json)");
  console.log("  Photo up   : POST /api/upload-image (writes assets/images/<file>)");
  console.log("  Geocode    : GET  /api/geocode?q=<address>");
  console.log("  Shell      : POST /api/exec   ⚠ runs host commands — loopback only, never expose\n");
});
