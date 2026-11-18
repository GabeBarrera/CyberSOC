# CyberSOC v2.0

Single-page SOC console: status map, alert feed and command line, dossier,
documentation files, and an RSS log view.

- **Data:** Firebase Authentication + Cloud Firestore (`soc_roles`,
  `soc_dossier`, `soc_files`, `soc_sitrep`, `soc_feeds`).
- **Access:** `admin` reads and writes, `viewer` reads (never confidential
  dossier files), everyone else sees fictional dummy data with a badge.
- **Feeds:** RSS (Azure, Microsoft 365, Power Platform, SolarWinds, plus your
  own) and threat intel, fetched through a read-only Cloudflare Worker.

There is no application server. `index.html` is the whole app.

**Setup, Firebase config and rules, Worker deploy, migration and
troubleshooting are in [`instructions.html`](instructions.html).**

## Quick start

1. In the Firebase console enable Google and Email/Password sign-in, create
   the Firestore database, and publish `firestore.rules`.
2. Serve this folder over http (`python3 -m http.server 8080`, or
   `py -m http.server 8080` on Windows) and open `http://localhost:8080`.
3. Sign in, then set your `soc_roles/<uid>` document's `role` to `admin` in
   the Firebase console.
4. Deploy `worker/` as the Worker `proxy-cybersoc` with Cloudflare Workers Builds (import this GitHub repo,
   root directory `worker`), then set `WORKER_URL` in `index.html` or paste it into
   SETTINGS → Feed proxy.
5. Optional: SETTINGS → Import legacy data to load the files in `legacy-data/`.

## Layout

| Path | Purpose |
| --- | --- |
| `index.html` | The app |
| `instructions.html` | Full instructions |
| `privacy.html` | Privacy Notice and Acceptable Use terms (accepted at sign-in) |
| `firestore.rules`, `firebase.json`, `.firebaserc` | Optional: only for deploying with the Firebase CLI; the app never reads them |
| `worker/` | Cloudflare Worker (feed proxy) |
| `assets/` | Favicon, manifest, placeholder silhouettes |
| `legacy-data/` | Old JSON data, for one-time import only — do not host |
