# 3x-ui + nginx + Psiphon multi-location

```text
rooye VPS (root):
  git clone <repo>
  cd <repo>
  python3 install.py

soal ha finglish-an.
keshvar:  7 20 26 28   ya   DE NL US SG
html:     1=default  2=file  3=folder
panel:    API token + URL  -> inbound + outbound + routing + Hosts :443
```

Installer for one VPS:

- fake HTTPS site on **port 443** (nginx reverse proxy)
- one **Psiphon** process per country (`EgressRegion`)
- matching **3x-ui** VLESS+WS inbounds on `127.0.0.1`
- routing: inbound tag → that country's SOCKS
- panel **Hosts** so copy-link is `domain:443` + TLS (not the internal listen port)

Terminal prompts are **finglish / ASCII** so a Linux console without Persian fonts still works.
Country list shows **flag emoji** (🇩🇪 DE Alman). Names stay finglish. If a console has no emoji font, the flag may look like two letters — codes still work.

```
client  --TLS:443/path-->  nginx  -->  Xray inbound (localhost)
                                      -->  socks 127.0.0.1:108x
                                      -->  psiphon-tunnel-core (DE/NL/US/…)
                                      -->  internet that country
```

## Requirements

- Ubuntu/Debian VPS, **root**
- Python 3.10+ (stdlib only, no `pip`)
- 3x-ui already installed, API token enabled
- TLS cert for the domain (`fullchain.pem` + `privkey.pem`)
- Port **443 free for nginx** (disable Reality/Xray on 443 first)

1 CPU / 2 GB RAM: **4–6 countries** is enough. Each Psiphon process is ~40 MB idle; traffic is **doubled** (in to VPS + out to Psiphon).

## Install on the VPS

```bash
git clone https://github.com/<you>/sanai-xui-psiphone-multi-location.git
cd sanai-xui-psiphone-multi-location
python3 install.py
```

Dry-run (no root, writes `build/` only):

```bash
python3 install.py --dry-run
```

### Prompts

1. Country list with numbers. Type `7 20 26 28` or `1,2,5` or `7-10` or codes `DE NL US SG`.
2. TLS: scans cert folders + nginx. Lists **domains by number**. Type `1` or `c` = custom domain + pem paths.
3. Fake site HTML: default template / one file / a folder (`index.html` + css/js).
4. nginx yes/no. Optional xHTTP location (`/blog` → `127.0.0.1:10088`).
5. 3x-ui yes/no: reads local panel db/CLI (`/etc/x-ui/x-ui.db`) for port, webBasePath, API token. Asks for token only if missing. Then source inbound to clone + optional client email.

Each country gets a **random common website path** from `data/common-paths.txt` (`/cdn/static/js/app.min.js`, `/_next/static/chunks/main.js`, …) — not `/ws-de`. Paths are unique per install. `n` on the confirm prompt rerolls. Client URI still appends `?ed=2560` (WebSocket early-data); nginx matches the path **without** the query.

Installer then:

1. downloads `psiphon-tunnel-core` → `/opt/psiphon/`
2. systemd `psiphon-<cc>.service` per country (own datadir — shared datadir crashes)
3. nginx site + WS locations `/ws-<cc>`
4. 3x-ui inbound + Hosts `:443` + socks outbound + **DNS rule scoped to those inbound tags only** (port 53 → `dns-out`). Other inbounds keep the panel DNS you already set.

## After install

```bash
python3 status.py
curl -I https://YOUR.DOMAIN/
```

Client link is always:

`vless://UUID@YOUR.DOMAIN:443?...&security=tls&sni=YOUR.DOMAIN&type=ws&path=/cdn/static/js/app.min.js?ed=2560`

Do **not** use the raw panel listen port (`10102`, `security=none`). Path is whatever the installer printed for that country.

Stop Psiphon units (does not delete panel inbounds):

```bash
python3 uninstall.py
```

## Country codes (Psiphon `EgressRegion`)

AT BE BG CA CH CZ DE DK EE ES FI FR GB HU IE IN IT JP LV NL NO PL RO RS SE SG SK US

List can change. Invalid code = tunnel fail or fallback.

Preset listen/SOCKS ports (paths are **random**, not `/ws-xx`):

| CC | Xray listen     | SOCKS |
|----|-----------------|-------|
| US | 127.0.0.1:10101 | 1081  |
| DE | 127.0.0.1:10102 | 1082  |
| NL | 127.0.0.1:10103 | 1083  |
| SG | 127.0.0.1:10104 | 1084  |

Other codes start at listen `10110` / SOCKS `1090`.

`?ed=2560` is Xray WebSocket early data (first 2560 bytes of the tunnel in the HTTP Upgrade). It is **not** part of the nginx `location`. Keep it on the client/Xray path.

## Layout on disk (VPS)

```
/opt/psiphon/psiphon-tunnel-core-x86_64
/opt/psiphon/de.config          # EgressRegion, ports, DataStoreDirectory
/opt/psiphon/data-de/           # MUST be unique per country
/etc/systemd/system/psiphon-de.service
/etc/nginx/sites-available/<domain>.conf
/var/www/<domain>/index.html
/opt/psiphon/install-state.json # last run, no API token
```

## Important pitfalls

- One broken 3x-ui inbound takes **all** of Xray down. Disable, don't delete.
- Do not send `allowInsecure` or empty `pinnedPeerCertSha256` (Xray 26).
- `shareAddrStrategy=custom` still prints the listen port in panel links — Hosts override is required.
- If the source inbound uses ML-KEM, keep `encryption=` on the client URI.
- nginx 1.24: `listen 443 ssl http2;` — not `http2 on;`.
- Reality and nginx cannot both bind 443.
- SOCKS does not carry UDP DNS well → installer adds `dns-out` **only on Psiphon inbound tags**. Direct / Reality / other inbounds still use the DNS block already in the 3x-ui panel.
- Telegram can work while Chrome shows `dns_probe` if that scoped DNS rule is missing on the Psiphon inbound.

## Suggestions (not in the script)

- Unique random paths instead of `/ws-de` if you publish many servers.
- Let's Encrypt via certbot, then point the installer at those pem files.
- `sysctl` BBR + `net.core.default_qdisc=fq`.
- fail2ban on SSH; keep the panel port off 443.
- Cap concurrent countries on small VPS; add a second VPS rather than 15 Psiphon processes.
- Psiphon exits are datacenter IPs, not residential. Streaming/banks may still flag them.
- Back up `/usr/local/x-ui/bin/config.json` before a panel routing update.
- Do not commit API tokens, panel paths, or certs. `state.local.json` is gitignored.

## License

MIT. Psiphon binary is downloaded from [Psiphon-Labs binaries](https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries) at install time — their license applies to that binary.
