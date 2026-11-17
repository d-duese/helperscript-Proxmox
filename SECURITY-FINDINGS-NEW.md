# New security findings (helperscript-Proxmox)

Validated NEW high-impact issues in `install/*.sh`, `ct/*.sh`, `misc/*.sh`, `vm/*.sh`, and `turnkey/*.sh` that are **not** duplicates of the already-reported set (code-server, webmin, filebrowser, octoprint, mongodb, photoprism, qbittorrent, syncthing, build.func privileged devices.allow, iventoy, neo4j, watchyourlan, glances, wireguard, keycloak, technitiumdns, owncast, traefik, zabbix, olivetin, nocodb, changedetection, fhem, lldap, openwebui, netdata, pialert, node-red, go2rtc, homeassistant/portainer, rabbitmq, archivebox, esphome, motioneye, shinobi, kubo, n8n, deluge, gotify, nzbget, sabnzbd, hivemq, emqx, influxdb, meshcentral, cronicle, nginxproxymanager, omv, casaos, calibre-web, homebridge, transmission, grafana, adguard, frigate, apt-cacher-ng, pocketbase, zwave-js-ui, jackett, agentdvr, gokapi).

Each finding was confirmed by reading the installer **and** companion `ct/*.sh` (bind address / auth / password randomness / advertised URL / `CT_TYPE`).

---

## 1. CRITICAL — Unmanic privileged LXC with unauthenticated UI (plugin RCE)

| Field | Value |
| --- | --- |
| **severity** | critical |
| **location** | `install/unmanic-install.sh` |
| **title** | Unmanic runs in a privileged CT with no UI/API authentication |
| **CT_TYPE** | `0` (privileged) — `ct/unmanic.sh:32` |
| **Bind / auth** | Listens on all interfaces port 8888; no password or auth configured |
| **Password** | N/A — Unmanic has no built-in auth |
| **Advertised URL** | `http://{IP}:8888` — `ct/unmanic.sh:70-71` |

**description:** `ct/unmanic.sh` defaults to a privileged container (`CT_TYPE="0"`), so `misc/build.func` grants host-device allow-all. The installer starts `unmanic` via systemd with no reverse-proxy auth and no application credentials. Unmanic’s UI/API are documented to have no login; the plugin system can execute arbitrary commands and rewrite library settings.

**impact:** A LAN attacker gets full control of the media optimiser (install malicious plugins → host command execution in a privileged LXC). Combined with `devices.allow: a`, guest root can escape to the Proxmox host.

**attack_path:**
1. Operator deploys Unmanic via `ct/unmanic.sh` (privileged by default).
2. `unmanic-install.sh` enables `unmanic.service` with no auth; CT script advertises port 8888.
3. Attacker opens `http://{guest}:8888` with no login.
4. Attacker installs a plugin or uses mutating API routes to run code as the service user; privileged device policy enables later host escape.

**evidence:** `install/unmanic-install.sh:43-61`, `ct/unmanic.sh:31-32`, `ct/unmanic.sh:69-71`, `misc/build.func:575-587`

**remediation:** Default to unprivileged CT; bind Unmanic to `127.0.0.1` and put HTTP Basic Auth (or an authenticated proxy) in front of UI/API before publishing; do not expose port 8888 on the LAN.

**why_not_duplicate:** Unmanic is not in the already-reported list. Distinct from Frigate/Tdarr/media apps already covered.

---

## 2. CRITICAL — HyperHDR privileged LXC with vendor default password `hyperhdr`

| Field | Value |
| --- | --- |
| **severity** | critical |
| **location** | `install/hyperhdr-install.sh` |
| **title** | HyperHDR privileged CT ships the documented default web password |
| **CT_TYPE** | `0` (privileged) — `ct/hyperhdr.sh:33` |
| **Bind / auth** | UI on `:8090` (all interfaces); auth uses vendor default until changed |
| **Password** | Vendor default `hyperhdr` (not randomized by installer) |
| **Advertised URL** | `http://{IP}:8090` — `ct/hyperhdr.sh:71-72` |

**description:** Privileged CT plus `hyperhdr.service` started with no password override. HyperHDR documents that a fresh install warns to change the password and that `--resetPassword` restores the well-known default `hyperhdr`. The installer never sets a unique password.

**impact:** LAN attacker authenticates as HyperHDR admin, controls LED/capture pipelines, and sits inside a privileged LXC with host-device allow-all.

**attack_path:**
1. Operator deploys HyperHDR via `ct/hyperhdr.sh`.
2. Installer enables HyperHDR without replacing the default password; CT prints port 8090.
3. Attacker logs in with the documented default password `hyperhdr`.
4. Attacker administers the instance; privileged CT remains available for host escape after guest root.

**evidence:** `install/hyperhdr-install.sh:31-47`, `ct/hyperhdr.sh:32-33`, `ct/hyperhdr.sh:70-72`, `misc/build.func:575-587`

**remediation:** Generate a random UI password at install (or force `--resetPassword` then set a unique hash), bind UI to localhost, default to unprivileged CT with only required USB/video devices.

**why_not_duplicate:** HyperHDR is not in the already-reported list (Hyperion unprivileged sibling also unreported but weaker).

---

## 3. CRITICAL — Dockge first visitor becomes Docker admin

| Field | Value |
| --- | --- |
| **severity** | critical |
| **location** | `install/dockge-install.sh` |
| **title** | Dockge is published so the first visitor owns Docker Compose management |
| **CT_TYPE** | `1` (unprivileged) — nesting/Docker |
| **Bind / auth** | Dockge on `:5001`; no admin pre-created |
| **Password** | First registrant becomes owner |
| **Advertised URL** | `http://{IP}:5001` — `ct/dockge.sh:71-72` |

**description:** Installer installs Docker and starts Dockge via `docker compose up -d` with the upstream compose file. Dockge treats the first registered user as administrator and can manage compose stacks via the Docker engine. No owner is created before the URL is advertised.

**impact:** Whoever opens the setup page first can launch arbitrary containers (including privileged ones if the engine allows), equivalent to root on the guest and a foothold on the LAN.

**attack_path:**
1. Operator deploys Dockge via `ct/dockge.sh`.
2. `dockge-install.sh` starts Dockge without creating an admin.
3. Attacker opens the advertised URL and completes first-user signup.
4. As Dockge admin the attacker deploys malicious compose stacks via Docker.

**evidence:** `install/dockge-install.sh:29-48`, `ct/dockge.sh:70-72`

**remediation:** Create the Dockge owner non-interactively before binding to a non-loopback address; bind to localhost until setup finishes; do not advertise `:5001` on the LAN until an admin exists.

**why_not_duplicate:** Dockge is not in the already-reported list (distinct from CasaOS/Portainer/Home Assistant findings).

---

## 4. CRITICAL — Umbrel first visitor owns a Docker app platform

| Field | Value |
| --- | --- |
| **severity** | critical |
| **location** | `install/umbrel-install.sh` |
| **title** | Umbrel first-run signup is advertised on the LAN with Docker installed |
| **CT_TYPE** | unprivileged with Docker |
| **Bind / auth** | Web UI on guest IP; first user becomes owner |
| **Password** | First registrant |
| **Advertised URL** | `http://{IP}` — `ct/umbrel.sh:69-70` |

**description:** Installer runs `bash <(curl -fsSL https://umbrel.sh)`, enables `umbrel-startup.service`, and leaves Umbrel’s first-run owner signup on the guest IP. Umbrel manages Docker apps; owner access is full control of the appliance.

**impact:** First visitor owns Umbrel and can install/run apps with Docker privileges on the guest.

**attack_path:**
1. Operator deploys Umbrel via `ct/umbrel.sh`.
2. Upstream installer starts the UI without a pre-created owner.
3. Attacker opens the advertised URL and creates the initial account.
4. Attacker installs apps / controls Docker-backed services.

**evidence:** `install/umbrel-install.sh:22-29`, `ct/umbrel.sh:68-70`

**remediation:** Complete Umbrel owner creation in the installer before publishing port 80; bind UI to localhost until setup finishes.

**why_not_duplicate:** Umbrel is not in the already-reported list (distinct from CasaOS).

---

## 5. CRITICAL — BunkerWeb setup wizard claims WAF/reverse-proxy admin

| Field | Value |
| --- | --- |
| **severity** | critical |
| **location** | `install/bunkerweb-install.sh` |
| **title** | BunkerWeb is installed with `UI_WIZARD=1` and `/setup` advertised |
| **CT_TYPE** | unprivileged |
| **Bind / auth** | Setup wizard on HTTP until first admin exists |
| **Password** | First visitor creates admin |
| **Advertised URL** | `http://{IP}/setup` — `ct/bunkerweb.sh:85-86` |

**description:** Installer exports `UI_WIZARD=1` then installs BunkerWeb. The CT script explicitly advertises the setup URL. Completing the wizard makes the visitor administrator of the WAF/reverse proxy.

**impact:** Attacker who finishes `/setup` first controls reverse-proxy/WAF policy and can intercept or redirect later-proxied services.

**attack_path:**
1. Operator deploys BunkerWeb via `ct/bunkerweb.sh`.
2. Installer sets `UI_WIZARD=1` and starts BunkerWeb.
3. Attacker opens `http://{guest}/setup` before the operator.
4. Attacker becomes BunkerWeb admin and rewrites proxy/WAF rules.

**evidence:** `install/bunkerweb-install.sh:37-38`, `ct/bunkerweb.sh:84-86`

**remediation:** Create the admin non-interactively (or bind setup to localhost), disable the wizard after install, and do not advertise `/setup` on the LAN.

**why_not_duplicate:** BunkerWeb is not in the already-reported list (distinct from Traefik/NPM).

---

## 6. CRITICAL — ioBroker admin UI has authentication disabled

| Field | Value |
| --- | --- |
| **severity** | critical |
| **location** | `install/iobroker-install.sh` |
| **title** | ioBroker admin is started without authentication on port 8081 |
| **CT_TYPE** | unprivileged |
| **Bind / auth** | Admin on `0.0.0.0:8081`; auth off until operator enables it |
| **Password** | None required until auth is turned on |
| **Advertised URL** | `http://{IP}:8081` — `ct/iobroker.sh:70-71` |

**description:** Installer runs the upstream ioBroker installer and never enables admin authentication or sets an admin password. ioBroker documents that a fresh admin UI requires no login and that anyone who can reach it can change everything (adapters, scripts, devices).

**impact:** Unauthenticated full control of a home-automation platform, including installing adapters that execute code on the guest.

**attack_path:**
1. Operator deploys ioBroker via `ct/iobroker.sh`.
2. Installer leaves admin auth disabled; CT advertises port 8081.
3. Attacker opens the URL with no login prompt.
4. Attacker installs adapters/scripts and controls attached IoT integrations.

**evidence:** `install/iobroker-install.sh:35-37`, `ct/iobroker.sh:69-71`

**remediation:** Set an admin password and enable authentication on `admin.0` before publishing port 8081; bind admin to localhost plus an authenticated proxy.

**why_not_duplicate:** ioBroker is not in the already-reported list.

---

## 7. HIGH — Apache Cassandra exposed with AllowAllAuthenticator

| Field | Value |
| --- | --- |
| **severity** | high |
| **location** | `install/apache-cassandra-install.sh` |
| **title** | Cassandra client RPC is rebound off localhost with authentication left disabled |
| **CT_TYPE** | `1` |
| **Bind / auth** | `rpc_address` switched from localhost to `eth0` via `rpc_interface`; authenticator remains default `AllowAllAuthenticator` |
| **Password** | None (AllowAll) |
| **Advertised URL** | No UI URL (DB port 9042) |

**description:** After installing Cassandra, the installer comments `rpc_address: localhost` and enables `rpc_interface: eth0`, exposing the native client transport on the container’s LAN address. It never sets `authenticator: PasswordAuthenticator` or creates roles. Cassandra’s default is AllowAllAuthenticator.

**impact:** Any network client can connect with cqlsh/drivers, read/write/drop keyspaces, and wipe or poison data.

**attack_path:**
1. Operator deploys Apache Cassandra via `ct/apache-cassandra.sh`.
2. Installer rebinds client RPC to eth0 without enabling auth.
3. Attacker connects to native port 9042 with no credentials.
4. Attacker enumerates and modifies all keyspaces.

**evidence:** `install/apache-cassandra-install.sh:31-37`, `ct/apache-cassandra.sh:33-34`

**remediation:** Leave `rpc_address` on localhost; if remote access is required, enable `PasswordAuthenticator`, create roles before exposing 9042, and firewall to trusted clients.

**why_not_duplicate:** Cassandra is not in the already-reported list (MongoDB/Influx/HiveMQ/EMQX were reported separately).

---

## 8. HIGH — deCONZ privileged CT + HTTP package trust chain

| Field | Value |
| --- | --- |
| **severity** | high |
| **location** | `install/deconz-install.sh` |
| **title** | Privileged deCONZ CT installs Phoscon over HTTP and publishes UI on port 80 |
| **CT_TYPE** | `0` (privileged) — `ct/deconz.sh:32` |
| **Bind / auth** | `deCONZ --http-port=80` as root; no UI password set by installer |
| **Password** | Not configured by script |
| **Advertised URL** | `http://{IP}` — `ct/deconz.sh:70-71` |

**description:** Privileged CT. Installer fetches the Phoscon APT signing key and repo over **HTTP** (`http://phoscon.de/...`) and downloads `libssl1.1` over **HTTP** from Ubuntu security, then installs `deconz` and starts it as root on port 80. A LAN MITM can replace the key/packages. The Phoscon/deCONZ UI is then advertised on the guest IP inside a privileged container with `devices.allow: a`.

**impact:** MITM during install yields root code execution in a privileged LXC (host-escape path). Independently, the Zigbee gateway UI/API surface is published on the LAN without installer-enforced credentials.

**attack_path:**
1. Operator deploys deCONZ via `ct/deconz.sh` (privileged).
2. Installer pulls key/repo/libssl over HTTP and starts deCONZ on `:80`.
3. Attacker either MITMs the HTTP fetches to plant a malicious package, or interacts with the published Phoscon UI/API on the LAN.
4. Privileged device allow-all remains available after guest compromise.

**evidence:** `install/deconz-install.sh:22-54`, `ct/deconz.sh:31-32`, `ct/deconz.sh:69-71`, `misc/build.func:575-587`

**remediation:** Use HTTPS-only APT sources and verify package checksums; set Phoscon/deCONZ credentials before publishing; default to unprivileged CT with only the Zigbee USB device allowed.

**why_not_duplicate:** deCONZ is not in the already-reported list (distinct from zigbee2mqtt/zwave-js-ui).

---

## 9. HIGH — Channels DVR privileged CT; first OAuth claimant owns the DVR

| Field | Value |
| --- | --- |
| **severity** | high |
| **location** | `install/channels-install.sh` |
| **title** | Privileged Channels DVR setup URL is published for the first Channels account to claim |
| **CT_TYPE** | `0` (privileged) — `ct/channels.sh:32` |
| **Bind / auth** | Setup on `:8089`; claims via Channels account OAuth |
| **Password** | N/A — first successful Channels login owns the server |
| **Advertised URL** | `http://{IP}:8089` — `ct/channels.sh:67-68` |

**description:** Privileged CT with hardware-acceleration device mounts. Installer runs Channels’ setup script and never pre-claims the DVR. Channels documents that the web admin on 8089 asks the visitor to authenticate with a Channels account; that account becomes the DVR owner. The CT script advertises the setup URL on the LAN.

**impact:** A LAN attacker who completes OAuth first links the privileged DVR to their Channels account (recordings, sources, settings). Privileged device policy amplifies later guest compromise.

**attack_path:**
1. Operator deploys Channels via `ct/channels.sh` (privileged).
2. Installer starts Channels DVR; CT advertises `http://{IP}:8089`.
3. Attacker opens the URL and authenticates with their Channels account before the operator.
4. Attacker owns the DVR configuration; privileged CT remains for host escape after guest root.

**evidence:** `install/channels-install.sh:38-42`, `ct/channels.sh:31-32`, `ct/channels.sh:66-68`, `misc/build.func:575-587`

**remediation:** Do not advertise `:8089` until the operator completes claim on localhost; default to unprivileged CT with only required dri/USB devices.

**why_not_duplicate:** Channels is not in the already-reported list.

---

## 10. HIGH — Grocy ships documented default `admin` / `admin`

| Field | Value |
| --- | --- |
| **severity** | high |
| **location** | `install/grocy-install.sh` |
| **title** | Grocy is published with the upstream default administrator unchanged |
| **CT_TYPE** | unprivileged |
| **Bind / auth** | Apache vhost on `:80`; default login remains |
| **Password** | Vendor default `admin` / `admin` |
| **Advertised URL** | `http://{IP}` — `ct/grocy.sh:80-81` |

**description:** Installer unpacks Grocy, copies `config-dist.php` to `data/config.php`, enables the Apache site, and never changes the seeded administrator. Grocy’s README documents default login `admin` / `admin`.

**impact:** Network attacker logs in as admin, reads/modifies household inventory, shopping, and user data, and can change Grocy configuration.

**attack_path:**
1. Operator deploys Grocy via `ct/grocy.sh`.
2. Installer starts Apache with stock Grocy data (default admin).
3. Attacker opens the advertised URL and authenticates as `admin`/`admin`.
4. Attacker controls the Grocy instance.

**evidence:** `install/grocy-install.sh:36-62`, `ct/grocy.sh:79-81`

**remediation:** Change the admin password non-interactively before publishing the vhost; bind to localhost plus an authenticated proxy.

**why_not_duplicate:** Grocy is not in the already-reported list.

---

## 11. HIGH — Alpine LXC hardcodes root password `alpine`

| Field | Value |
| --- | --- |
| **severity** | high |
| **location** | `ct/alpine.sh` |
| **title** | Default Alpine CT root password is the public string `alpine` |
| **CT_TYPE** | `1` |
| **Bind / auth** | Root password set via `pct` `-password alpine` |
| **Password** | Hardcoded `alpine` |
| **SSH** | Default `SSH="no"`; advanced mode can set `SSH="yes"` which enables `PermitRootLogin yes` via `alpine-install.func` |

**description:** `default_settings` sets `PW="-password alpine"`. Every default Alpine helper-script CT therefore has a publicly known root password. When SSH root login is enabled (advanced option), `misc/alpine-install.func` sets `PermitRootLogin yes` and starts sshd — yielding remote root with password `alpine`. The same pattern exists in `ct/rockylinux.sh` with password `rockylinux`.

**impact:** Remote root login to every default Alpine (or Rocky) CT once SSH root is enabled; full guest compromise and pivot.

**attack_path:**
1. Operator creates Alpine CT with defaults (or enables SSH in advanced settings without changing the password).
2. Container root password is the known value from the public script.
3. Attacker SSHs as `root` with password `alpine` (when SSH root password login is on).
4. Attacker owns the guest.

**evidence:** `ct/alpine.sh:32-34`, `ct/alpine.sh:50`, `misc/alpine-install.func:107-110`, related: `ct/rockylinux.sh:32-34`

**remediation:** Generate a random root password (or force the operator to set one); never hardcode credentials in `default_settings`; keep `PermitRootLogin prohibit-password` / key-only.

**why_not_duplicate:** Alpine/Rocky root password hardcoding is not in the already-reported list.

---

## 12. HIGH — Alpine install path deletes root password when `PASSWORD` is empty

| Field | Value |
| --- | --- |
| **severity** | high |
| **location** | `misc/alpine-install.func` |
| **title** | Alpine guests with empty `PW` run `passwd -d root` |
| **Applies to** | Alpine app CTs that set `PW=""` (e.g. `ct/alpine-zigbee2mqtt.sh`, `ct/alpine-docker.sh`, `ct/alpine-grafana.sh`, …) |
| **CT_TYPE** | Includes privileged `alpine-zigbee2mqtt` (`CT_TYPE="0"`) |
| **Password** | Empty (password deleted) |

**description:** `customize()` checks `PASSWORD == ""` and runs `passwd -d root`, removing the root password entirely. Many Alpine app scripts default `PW=""`. Privileged `alpine-zigbee2mqtt` also installs `openssh` and, if SSH root is enabled, sets `PermitRootLogin yes`. Empty root password plus password auth is a classic lockout/bypass footgun on console and misconfigured SSH.

**impact:** Root account with no password on Alpine helper CTs (including privileged Zigbee2MQTT), enabling console login without credentials and amplifying any later SSH misconfiguration.

**attack_path:**
1. Operator deploys an Alpine app CT with default empty password (e.g. Alpine-Zigbee2MQTT).
2. `alpine-install.func` deletes the root password.
3. Attacker with console access (or SSH if empty passwords / root login are permitted) becomes root without a secret.
4. On privileged alpine-zigbee2mqtt, guest root plus `devices.allow: a` enables host-escape potential.

**evidence:** `misc/alpine-install.func:114-118`, `ct/alpine-zigbee2mqtt.sh:32-34`, `install/alpine-zigbee2mqtt-install.sh:19-31`

**remediation:** Never `passwd -d root`. Require a random or operator-supplied password; keep SSH key-only; for Zigbee2MQTT set `frontend.auth_token` before exposing any UI.

**why_not_duplicate:** `alpine-install.func` / empty root password is not in the already-reported list. Complements finding 11 (hardcoded password) with the empty-password path used by Alpine *app* CTs.

---

## Noted but not scored as complete chains (omitted from cap)

- **Redis** (`install/redis-install.sh`): binds `0.0.0.0` but does not disable `protected-mode`; remote commands are denied without `requirepass` — incomplete remote exploit chain.
- **MariaDB / PostgreSQL**: listen-all without creating remotely usable passwords; unix_socket/peer still gate local root — incomplete unauthenticated remote DB.
- **MQTT (Mosquitto)**: `allow_anonymous false` with empty passwd file — denies clients rather than opening anonymous pub/sub.
- **Debian Zigbee2MQTT**: no `configuration.yaml` / frontend written; service enabled but UI auth issue not realized until operator enables frontend.
- **post-pve-install.sh**: subscription-nag patch / repo toggles — hardening/policy concern, not a remote exploit chain.

---

## Summary table

| # | Severity | Location | Issue class |
| --- | --- | --- | --- |
| 1 | critical | `install/unmanic-install.sh` | Privileged + unauth UI/API |
| 2 | critical | `install/hyperhdr-install.sh` | Privileged + vendor default password |
| 3 | critical | `install/dockge-install.sh` | First-visitor Docker admin |
| 4 | critical | `install/umbrel-install.sh` | First-visitor Docker admin |
| 5 | critical | `install/bunkerweb-install.sh` | First-visitor WAF/proxy admin |
| 6 | critical | `install/iobroker-install.sh` | Unauthenticated admin UI |
| 7 | high | `install/apache-cassandra-install.sh` | Unauth DB bind-all |
| 8 | high | `install/deconz-install.sh` | Privileged + HTTP install + UI |
| 9 | high | `install/channels-install.sh` | Privileged + first OAuth claim |
| 10 | high | `install/grocy-install.sh` | Hardcoded/vendor default creds |
| 11 | high | `ct/alpine.sh` | Hardcoded root password |
| 12 | high | `misc/alpine-install.func` | Empty root password (`passwd -d`) |
