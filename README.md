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
| Live Azure region status | `GET /api/azure-status` (proxies the public Azure status feed) |
| Live SolarWinds component status | `GET /api/solarwinds-status` (Atlassian Statuspage v2 JSON API) |
| Read roster | `GET /api/dossier` |
| Create / edit / delete (writes the file) | `PUT /api/dossier` → `data/soc_dossier.json` |
| Address geocoding for map pins | `GET /api/geocode?q=...` (proxies Nominatim) |

The **NEW / EDIT / DELETE** buttons in the Dossier persist straight to `data/soc_dossier.json` through the server. The nav badge reads **AZURE LIVE** when the proxy feed is active, **SIM FEED** when falling back.

## Views
- **Status ticker** — scrolling bar beneath the nav showing live operational status of Azure regions and/or SolarWinds Observability components (colored dots + labels). Source, visibility, issues-only filter, and scroll speed are all controlled in Settings. Hover to pause.
- **SITREP** — dark world map of Azure regions (green / amber / red), radar sweep from your live location that pings each region as the line crosses it. Right-edge **CMD** tab = command line (`help`, `sitrep`, `status <code>`, `alerts`, `scan`, `locate`, `clear`). Left-edge **ALERTS** tab = incident detail.
- **DOSSIER** — case files with photo, DOB, sex, race/ethnicity, description, and **relationships** (linked to other subjects; click a name to jump to their file). A subject's **last known location** is clickable → plots a pin on the SITREP map. The roster panel's **WEB VIEW** shows all subjects as draggable cards with connector lines.
- **SETTINGS** — theme (dark / light, also swaps the map basemap), accent color, ticker source/visibility/speed, radar sweep on-off + speed, auto-refresh interval, and reduce-motion. Saved to `localStorage`.
- **LOG** — placeholder.

## Notes
- The Azure proxy scrapes the public status feed (best-effort). For production fidelity, swap `getAzureStatus()` in `server.js` for the **Azure Service Health API** (`Microsoft.ResourceHealth`) with a token held server-side.
- The SolarWinds proxy uses the official Atlassian Statuspage v2 JSON API — clean and stable, no scraping.
- Without the server, the ticker and map run on simulated status data so the page still demos fully.
- Nominatim has a usage policy — fine for light/local use; don't hammer it.
