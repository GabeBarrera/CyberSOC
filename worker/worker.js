/* ===================================================================
   CyberSOC — Cloudflare Worker (read-only feed proxy)

   Replaces the old local Node server. It holds no secrets and writes
   nothing: every route is a GET that fetches public data on the
   browser's behalf (the browser can't, because of CORS).

     GET /api/health               liveness
     GET /api/rss?url=<feed>       RSS / Atom proxy (XML only, 2 MB cap)
     GET /api/threat-intel?cats=   CISA KEV · Feodo · ThreatFox · URLhaus · Tor ·
                                   ransomware.live · OpenSky — only the listed
                                   categories are fetched (cached 60s)
     GET /api/ip-intel?q=<ip|host> geolocation + ASN (ip-api.com)
     GET /api/downdetector?q=<svc> DownDetector 24h report series (best effort)
     GET /api/downdetector-status  Azure / SolarWinds / Cloudflare watchlist

   Access control: only origins listed in the ALLOWED_ORIGINS variable
   (wrangler.toml) receive a response. See instructions.html.
   =================================================================== */

const JSON_HEADERS = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" };

/* ---------- origin allowlist ---------- */
function allowedOrigin(request, env) {
  const list = String((env && env.ALLOWED_ORIGINS) || "").split(",").map((s) => s.trim().replace(/\/$/, "")).filter(Boolean);
  if (list.includes("*")) return "*";
  const origin = request.headers.get("Origin");
  if (origin && list.includes(origin)) return origin;
  return null;
}
function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Accept",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
    "X-Content-Type-Options": "nosniff"
  };
}
function json(obj, status, origin) {
  return new Response(JSON.stringify(obj), { status: status || 200, headers: Object.assign({}, JSON_HEADERS, corsHeaders(origin)) });
}

/* ---------- tiny per-isolate TTL cache ---------- */
const _cache = new Map();
async function cached(key, ttlMs, producer) {
  const hit = _cache.get(key);
  if (hit && Date.now() - hit.ts < ttlMs) return hit.value;
  if (hit && hit.pending) return hit.pending;
  const pending = Promise.resolve().then(producer).then(
    (value) => { _cache.set(key, { ts: Date.now(), value }); return value; },
    (err) => { if (hit && hit.value !== undefined) { _cache.set(key, { ts: hit.ts, value: hit.value }); return hit.value; } _cache.delete(key); throw err; }
  );
  _cache.set(key, Object.assign({}, hit || { ts: 0 }, { pending }));
  return pending;
}

/* ---------- RSS / Atom proxy ---------- */
const RSS_MAX_BYTES = 2 * 1024 * 1024;
const RSS_UA = "CyberSOC-Worker/2.0 (+rss)";
/* Refuse anything that is not a public http(s) host. Workers cannot reach a
   private network anyway; this just keeps the proxy from being pointed at
   loopback / link-local / RFC1918 literals or single-label internal names. */
function isPublicHttpUrl(u) {
  if (u.protocol !== "https:" && u.protocol !== "http:") return false;
  if (u.username || u.password) return false;
  const h = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!h.includes(".") && !h.includes(":")) return false;                // localhost, intranet names
  if (/\.(local|internal|localhost|lan|home|corp)$/.test(h)) return false;
  if (h.includes(":")) return !/^(::1?$|f[cd]|fe80|::ffff:)/.test(h);     // IPv6 loopback / ULA / link-local / mapped
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
  }
  return true;
}
async function proxyFeed(target) {
  let u;
  try { u = new URL(target); } catch (e) { throw Object.assign(new Error("invalid url"), { status: 400 }); }
  if (!isPublicHttpUrl(u)) throw Object.assign(new Error("url not allowed"), { status: 400 });
  return cached("rss:" + u.href, 120000, async () => {
    const r = await fetch(u.href, {
      redirect: "follow",
      headers: { "User-Agent": RSS_UA, "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.1" }
    });
    if (!r.ok) throw Object.assign(new Error("upstream http " + r.status), { status: 502 });
    const len = +(r.headers.get("content-length") || 0);
    if (len > RSS_MAX_BYTES) throw Object.assign(new Error("feed too large"), { status: 413 });
    const text = await r.text();
    if (text.length > RSS_MAX_BYTES) throw Object.assign(new Error("feed too large"), { status: 413 });
    if (!/<(rss|feed|rdf:RDF)[\s>]/i.test(text.slice(0, 4096))) throw Object.assign(new Error("not an RSS or Atom feed"), { status: 415 });
    return text;
  });
}

/* ---------- country centroids ---------- */

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
function geoForCountry(cc, seed) {
  if (!cc) return null;
  const c = COUNTRY_CENTROIDS[String(cc).toUpperCase()];
  if (!c) return null;
  // small deterministic jitter so multiple IPs in one country fan out
  const j = (s) => { let h = 0; for (const ch of String(s)) h = (h * 31 + ch.charCodeAt(0)) & 0xffff; return ((h % 1000) / 1000 - 0.5) * 6; };
  return { lat: c[0] + j(cc + seed + "lat"), lng: c[1] + j(cc + seed + "lng") };
}

async function fetchJSON(url, opts) {
  const r = await fetch(url, Object.assign({
    headers: { "User-Agent": "CyberSOC-Worker/2.0", "Accept": "application/json" }
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

/* ---- OpenSky Network — live aircraft state vectors (anonymous, no key,
   carries lat/lng directly). Cached for ~5 min so the 60s feed cycle does
   not blow the anonymous rate limit; on 429/error we serve the last snapshot.
   State-vector indices: 0 icao24 · 1 callsign · 2 origin_country · 4 last_contact
   · 5 lon · 6 lat · 7 baro_alt · 8 on_ground · 9 velocity(m/s) · 10 true_track
   · 13 geo_alt. We sample evenly to ~70 airborne flights to spread them globally
   and keep the payload small. */
const OPENSKY = "https://opensky-network.org/api/states/all";
let _openskyCache = { ts: 0, data: [] };
async function getOpenSky() {
  if (Date.now() - _openskyCache.ts < 290000 && _openskyCache.data.length) return _openskyCache.data;
  try {
    const j = await fetchJSON(OPENSKY);
    const states = Array.isArray(j.states) ? j.states : [];
    const flying = states.filter((s) => s[5] != null && s[6] != null && !s[8] && s[1] && String(s[1]).trim());
    const step = Math.max(1, Math.floor(flying.length / 70));
    const picked = [];
    for (let i = 0; i < flying.length && picked.length < 70; i += step) picked.push(flying[i]);
    const mapped = picked.map((s) => {
      const cs = String(s[1] || "").trim();
      const alt = s[13] != null ? s[13] : s[7];
      const kt = s[9] != null ? Math.round(s[9] * 1.94384) : null;
      const trk = s[10] != null ? Math.round(s[10]) : null;
      return {
        id: "air-" + s[0],
        cat: "AIR",
        sev: "info",
        title: cs || s[0],
        sub: "Aircraft \u00B7 " + (s[2] || "unknown origin"),
        msg: ["Live aircraft", alt != null ? "alt " + Math.round(alt) + " m" : "",
              kt != null ? kt + " kt" : "", trk != null ? "track " + trk + "\u00B0" : ""]
              .filter(Boolean).join(" \u00B7 "),
        ts: s[4] ? s[4] * 1000 : Date.now(),
        src: "OpenSky Network",
        lat: +s[6],
        lng: +s[5],
        hdg: trk != null ? trk : 0,
        geo: s[2] || undefined
      };
    });
    _openskyCache = { ts: Date.now(), data: mapped };
    return mapped;
  } catch (e) {
    if (_openskyCache.data.length) return _openskyCache.data; // serve stale on rate-limit / error
    throw e;
  }
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
        headers: { "User-Agent": "CyberSOC-Worker/2.0", "Content-Type": "application/json" },
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
      const g = geoForCountry(it.cc, it.id || "");
      if (g) { it.lat = g.lat; it.lng = g.lng; it.geo = it.geo || it.cc; centroid++; }
    }
  });
  return { precise, centroid };
}

/* In-memory cache + background refresher (every 60s; see startup). */

/* ---------- DownDetector search (best-effort scrape, no API key) ----------
   Resolves a free-text query ("azure") to a DownDetector status-page slug
   ("windows-azure"), then scrapes the page's embedded chart script for its
   24h report-volume series (same data DavideViolante/downdetector-api pulls,
   without the headless-browser dependency — the points are already present
   in the server-rendered HTML). Cloudflare occasionally blocks the .com
   domain for non-browser requests; callers get a clear error + a direct
   link to open manually when that happens. */
const DD_ALIASES = {
  azure: "windows-azure", "microsoft azure": "windows-azure", "windows azure": "windows-azure",
  aws: "amazon-web-services-aws", "amazon web services": "amazon-web-services-aws",
  "office 365": "office-365", "microsoft 365": "office-365", o365: "office-365",
  outlook: "outlook", hotmail: "outlook",
  teams: "microsoft-teams", "microsoft teams": "microsoft-teams",
  github: "github", gitlab: "gitlab", slack: "slack", discord: "discord",
  cloudflare: "cloudflare", google: "google", gmail: "gmail", youtube: "youtube",
  "google cloud": "google-cloud", gcp: "google-cloud",
  facebook: "facebook", instagram: "instagram", whatsapp: "whatsapp", messenger: "facebook-messenger",
  twitter: "twitter", x: "twitter", tiktok: "tiktok", reddit: "reddit", snapchat: "snapchat",
  zoom: "zoom", spotify: "spotify", netflix: "netflix",
  playstation: "playstation-network", psn: "playstation-network",
  xbox: "xbox-live", "xbox live": "xbox-live",
  steam: "steam", "epic games": "epic-games", fortnite: "fortnite",
  chatgpt: "openai", openai: "openai",
  verizon: "verizon", "at&t": "att", att: "att", "t-mobile": "t-mobile", tmobile: "t-mobile",
  comcast: "comcast-xfinity", xfinity: "comcast-xfinity", spectrum: "spectrum",
  paypal: "paypal", venmo: "venmo", "cash app": "cash-app", robinhood: "robinhood",
  coinbase: "coinbase", chase: "chase", "bank of america": "bank-of-america", "wells fargo": "wells-fargo",
  amazon: "amazon", ebay: "ebay", salesforce: "salesforce"
};
function ddSlugify(q) {
  return String(q || "").toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}
const DD_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";
async function ddResolveSlug(query) {
  const key = String(query || "").toLowerCase().trim();
  if (DD_ALIASES[key]) return { slug: DD_ALIASES[key], via: "alias" };
  try {
    const r = await fetch("https://downdetector.com/search/?q=" + encodeURIComponent(query),
      { headers: { "User-Agent": DD_UA, "Accept": "text/html" } });
    if (r.ok) {
      const html = await r.text();
      const m = html.match(/href="\/status\/([a-z0-9-]+)\/"/i);
      if (m) return { slug: m[1], via: "search" };
    }
  } catch (e) { /* fall through to guess */ }
  return { slug: ddSlugify(query), via: "guess" };
}
async function fetchDDPage(slug) {
  const url = "https://downdetector.com/status/" + slug + "/";
  const r = await fetch(url, { headers: { "User-Agent": DD_UA, "Accept": "text/html" } });
  if (!r.ok) throw Object.assign(new Error("downdetector http " + r.status), { url });
  const html = await r.text();
  const titleM = html.match(/<title>([^<]+)<\/title>/i);
  const name = titleM ? titleM[1].replace(/\s*Outage.*$/i, "").replace(/\s*\|.*$/, "").trim() : slug;
  const descM = html.match(/<meta[^>]+(?:name|property)="(?:og:)?description"[^>]+content="([^"]*)"/i);
  const summary = descM ? descM[1].replace(/&amp;/g, "&").replace(/&#39;/g, "'").replace(/&quot;/g, '"') : null;

  let dataScript = null;
  const scriptRe = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  let sm;
  while ((sm = scriptRe.exec(html))) {
    if (sm[1].includes("{ x:")) { dataScript = sm[1]; break; }
  }
  let reports = [], baseline = [];
  if (dataScript) {
    const pts = [];
    const ptRe = /\{\s*x:\s*'([^']+)',\s*y:\s*([\d.]+)\s*\}/g;
    let pm;
    while ((pm = ptRe.exec(dataScript))) pts.push({ date: pm[1], value: +pm[2] });
    const half = Math.floor(pts.length / 2);
    reports = half ? pts.slice(0, half) : pts;
    baseline = half ? pts.slice(half) : [];
  }
  const latest = reports.length ? reports[reports.length - 1].value : null;
  const base = baseline.length ? baseline[baseline.length - 1].value : null;
  let status = "unknown";
  if (latest != null && base != null) {
    if (latest > 5 && latest > base * 3) status = "outage";
    else if (latest > base * 1.5) status = "elevated";
    else status = "normal";
  }
  return { url, name, summary, status, reports, baseline };
}

/* ---- auto-scan: Azure / SolarWinds / Cloudflare on DownDetector, for the ticker ----
   Small fixed watchlist (no free-text resolution needed — slugs are known),
   refreshed on demand (cached 2 min) and served via /api/downdetector-status. */
const DD_WATCHLIST = [
  { key: "AZURE", slug: "windows-azure", name: "Azure" },
  { key: "SOLARWINDS", slug: "solarwinds", name: "SolarWinds" },
  { key: "CLOUDFLARE", slug: "cloudflare", name: "Cloudflare" }
];
const DOWNDETECTOR_STATUS = { fetchedAt: null, items: [] };
async function refreshDownDetectorStatus() {
  const results = await Promise.allSettled(DD_WATCHLIST.map((w) => fetchDDPage(w.slug)));
  const items = results.map((res, i) => {
    const w = DD_WATCHLIST[i];
    if (res.status === "fulfilled") {
      return { key: w.key, name: w.name, slug: w.slug, url: res.value.url, status: res.value.status, ok: true };
    }
    return { key: w.key, name: w.name, slug: w.slug, url: "https://downdetector.com/status/" + w.slug + "/", status: "unknown", ok: false, error: res.reason && res.reason.message };
  });
  DOWNDETECTOR_STATUS.fetchedAt = new Date().toISOString();
  DOWNDETECTOR_STATUS.items = items;
  return DOWNDETECTOR_STATUS;
}

/* ---------- threat intel aggregate (on demand, cached 60s) ----------
   ?cats=CVE,C2,… selects which sources are contacted; a category the console
   has switched off is never fetched. */
const INTEL_JOBS = {
  CVE: ["cisa", getCISA], C2: ["feodo", getFeodo], IOC: ["threatfox", getThreatFox], URL: ["urlhaus", getURLhaus],
  TOR: ["tor", getTor], RANSOM: ["ransomware", getRansomware], AIR: ["opensky", getOpenSky]
};
function intelCats(param) {
  const want = String(param || "").toUpperCase().split(",").map((s) => s.trim()).filter((c) => INTEL_JOBS[c]);
  return (want.length ? [...new Set(want)] : Object.keys(INTEL_JOBS)).sort();
}
async function buildThreatIntel(cats) {
  const jobs = cats.map((c) => INTEL_JOBS[c]);
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
  return { fetchedAt: new Date().toISOString(), cats, feeds, items, geo };
}

/* ---------- IP / host intel: geolocation + ASN (ip-api.com) ----------
   Domain registration (RDAP) is fetched by the browser directly — rdap.org
   sends CORS headers — so it is not duplicated here. */
async function ipIntel(raw) {
  const q = String(raw || "").trim().replace(/^[a-z]+:\/\//i, "").replace(/\/.*$/, "").replace(/^["']|["']$/g, "");
  if (!q || q.length > 253 || !/^[a-z0-9.:_-]+$/i.test(q)) throw Object.assign(new Error("invalid query"), { status: 400 });
  const out = { query: q, type: (IPV4.test(q) || q.includes(":")) ? "ip" : "domain", ok: false };
  try {
    const r = await fetch("http://ip-api.com/json/" + encodeURIComponent(q) +
      "?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,query",
      { headers: { "User-Agent": "CyberSOC-Worker/2.0" } });
    if (r.ok) {
      const j = await r.json();
      if (j && j.status === "success") {
        Object.assign(out, {
          ok: true, ip: j.query, country: j.country, countryCode: j.countryCode,
          region: j.regionName, city: j.city, lat: j.lat, lng: j.lon, timezone: j.timezone,
          isp: j.isp, org: j.org, as: j.as, asname: j.asname, reverse: j.reverse
        });
      } else if (j && j.message) out.error = j.message;
    }
  } catch (e) { out.error = e.message; }
  return out;
}

/* ---------- router ---------- */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname.replace(/\/+$/, "") || "/";
    const origin = allowedOrigin(request, env);
    if (!origin) return new Response("origin not allowed", { status: 403, headers: { "Content-Type": "text/plain" } });
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(origin) });
    if (request.method !== "GET") return json({ error: "method not allowed" }, 405, origin);

    try {
      if (p === "/api/health") return json({ ok: true, service: "CyberSOC worker", ts: new Date().toISOString() }, 200, origin);

      if (p === "/api/rss") {
        const xml = await proxyFeed(url.searchParams.get("url") || "");
        return new Response(xml, { status: 200, headers: Object.assign({ "Content-Type": "application/xml; charset=utf-8", "Cache-Control": "public, max-age=120" }, corsHeaders(origin)) });
      }

      if (p === "/api/threat-intel") {
        const cats = intelCats(url.searchParams.get("cats"));
        return json(await cached("threat-intel:" + cats.join(","), 60000, () => buildThreatIntel(cats)), 200, origin);
      }

      if (p === "/api/ip-intel") {
        const q = (url.searchParams.get("q") || "").trim();
        if (!q) return json({ error: "missing q" }, 400, origin);
        return json(await cached("ip:" + q.toLowerCase(), 600000, () => ipIntel(q)), 200, origin);
      }

      if (p === "/api/downdetector-status") return json(await cached("dd-status", 120000, refreshDownDetectorStatus), 200, origin);

      if (p === "/api/downdetector") {
        const q = (url.searchParams.get("q") || "").trim().slice(0, 80);
        if (!q) return json({ error: "missing q" }, 400, origin);
        const resolved = await ddResolveSlug(q);
        try {
          const page = await cached("dd:" + resolved.slug, 120000, () => fetchDDPage(resolved.slug));
          return json(Object.assign({ query: q, slug: resolved.slug, via: resolved.via, fetchedAt: new Date().toISOString() }, page), 200, origin);
        } catch (e) {
          // fall back to the RESOLVED slug's page, not the raw query
          return json({ error: "downdetector fetch failed", detail: String(e.message || e), url: e.url || ("https://downdetector.com/status/" + resolved.slug + "/") }, 502, origin);
        }
      }

      return json({ error: "not found" }, 404, origin);
    } catch (e) {
      return json({ error: String(e.message || e) }, e.status || 502, origin);
    }
  }
};
