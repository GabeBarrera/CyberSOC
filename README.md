# CyberSOC

All-domain SOC operations console — threat landscape map, command line, and a cyberpunk FBI-style dossier.

## Two ways to run

### 1. Static (GitHub Pages / any static host)
Just serve the folder. `index.html` is fully self-contained. Everything works **except** the live Azure feed and server-side file writes — it falls back to simulated status data and saves the dossier to your browser's `localStorage`. Use **EXPORT JSON** in the roster panel to download an updated `data/soc_dossier.json` to commit back.

### 2. Local with the Node server (recommended — unlocks live features)
Requires **Node 18+** (uses built-in `fetch`, no `npm install` needed).

```bash
node server.js
# → open http://localhost:3005
```

When served this way the page detects the API and goes live:

| Feature | Endpoint |
|---|---|
| Liveness probe (powers `server -s`) | `GET /api/health` |
| Live Azure region status | `GET /api/azure-status` (proxies the public Azure status feed) |
| Live SolarWinds component status | `GET /api/solarwinds-status` (Atlassian Statuspage v2 JSON API) |
| Public threat intel (powers `intel`) | `GET /api/threat-intel` (CISA KEV · Feodo C2 · ThreatFox · URLhaus · Tor · OpenSky aircraft; auto-refreshed ~60s, `?refresh=1` forces a re-pull) |
| Read roster | `GET /api/dossier` |
| Create / edit / delete (writes the file) | `PUT /api/dossier` → `data/soc_dossier.json` |
| Dossier photo upload | `POST /api/upload-image` → `assets/images/<file>` |
| Read / write country SITREP intel & alerts | `GET` / `PUT /api/sitrep` → `data/soc_sitrep.json` |
| Read / write log documentation repository | `GET` / `PUT /api/files` → `data/soc_files.json` |
| Address geocoding for map pins | `GET /api/geocode?q=...` (proxies Nominatim) |
| Host shell bridge (powers `localhost`) | `POST /api/exec` — ⚠ runs commands on the host; loopback-only, **never expose publicly** |

The **NEW / EDIT / DELETE** buttons in the Dossier persist straight to `data/soc_dossier.json` through the server. The nav badge reads **AZURE LIVE** when the proxy feed is active, **SIM FEED** when falling back.

## Views
- **Status ticker** — scrolling bar beneath the nav showing live operational status of Azure regions and/or SolarWinds Observability components (colored dots + labels). Source, visibility, issues-only filter, and scroll speed are all controlled in Settings. Hover to pause.
- **SITREP** — dark world map of Azure regions (green / amber / red), radar sweep from your live location that pings each region as the line crosses it. Public threat-intel pins (CVE · C2 · IOC · live aircraft) overlay the map with a toggleable legend, fed by `intel` / `/api/threat-intel`. Right-edge **CMD** tab = command line (see the **Command line** section below). Country threat postures (red = hostile, yellow = watchlist, blue = allied) outline a nation's border on the map; the editor logs **diplomacy** (At War / Allies with country auto-complete), a brief, and alerts (each with optional coordinates + an external link, an inline edit button, and created/modified timestamps). Country alerts persist to `data/soc_sitrep.json` (server) or `localStorage` (offline) and appear in the **ALERTS** feed under the **COUNTRY** filter.
- **DOSSIER** — case files with photo, DOB, sex, race/ethnicity, description, and **relationships** (linked to other subjects; click a name to jump to their file). A subject's **last known location** is clickable → plots a pin on the SITREP map. The roster panel's **WEB VIEW** shows all subjects as draggable cards with connector lines.
- **SETTINGS** — theme (dark / light, also swaps the map basemap), accent color, ticker source/visibility/speed, radar sweep on-off + speed, auto-refresh interval, and reduce-motion. Saved to `localStorage`.
- **LOG** — placeholder.

## Command line
Open it from the right-edge **CMD** tab on the SITREP view. Commands are single words; flags and parameters follow. Type `help` for the core list, or `<command> -h` (also `-help`) on any command with multiple flags to see its full parameter reference.

| Command | What it does |
|---|---|
| `help` | List the core commands with a one-line summary each. |
| `server` | Full situational report — Azure regions + SolarWinds Observability component status. |
| `server -s` | Node server reachability check (probes `/api/health`; reports live vs. offline mode). |
| `server -h` | Show the `server` flag reference. |
| `sitrep` | List every country alert created or modified in the last 24h. |
| `sitrep <country>` | Zoom + outline a country's border by threat posture and print its intel. Accepts ISO codes or names — e.g. `sitrep US`, `sitrep "United Kingdom"`. |
| `sitrep -m <country>` | Open the intel editor (posture · diplomacy · brief · alerts). |
| `sitrep -s` | Force a re-sync of the status feed. |
| `sitrep -h` | Show the `sitrep` flag/parameter reference. |
| `locate <keyword>` | Search the dossier (name, alias, city, affiliation…) and plot matching subjects' last-known locations on the map. With no keyword, prints the operator's current position. |
| `locate -f <flight>` | Center the map on a live flight pin by call sign — e.g. `locate -f UAL245`. With no code, lists tracked aircraft. |
| `locate -h` | Show the `locate` flag/parameter reference. |
| `alerts` | List active Azure incidents only. |
| `intel` | Public threat intelligence — CVEs (CISA KEV) · C2 (Feodo Tracker) · IOCs (ThreatFox), live when the server is reachable. |
| `localhost` | Open a live shell bridged to the host machine via the Node server; every line then executes on the host (`exit` to disconnect). `localhost <cmd>` runs a single command. Requires the local server. |
| `clear` | Clear the console. |

Use **↑ / ↓** to walk through recent command history.

## Notes
- The Azure proxy scrapes the public status feed (best-effort). For production fidelity, swap `getAzureStatus()` in `server.js` for the **Azure Service Health API** (`Microsoft.ResourceHealth`) with a token held server-side.
- The SolarWinds proxy uses the official Atlassian Statuspage v2 JSON API — clean and stable, no scraping.
- The threat-intel feed aggregates public sources (CISA KEV, abuse.ch Feodo Tracker / ThreatFox / URLhaus, the Tor exit list, and OpenSky aircraft states), normalizes them server-side, and caches with a background refresh. Aircraft are sampled to keep the payload small; OpenSky is rate-limited for anonymous use.
- Without the server, the ticker and map run on simulated status data so the page still demos fully.
- Nominatim has a usage policy — fine for light/local use; don't hammer it.
