<h1>MegaBasterd</h1>

[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/commit-activity) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

<p align="center"><i>"If it compiles, it's good; if it boots up, it's perfect." (Linus Torvalds)</i></p>
<p align="center"><a href="https://github.com/tonikelope/megabasterd/releases/latest" target="_blank"><img src="https://raw.githubusercontent.com/tonikelope/megabasterd/master/src/main/resources/images/mbasterd_logo_git.png"></a></p>
<h2 align="center"><a href="https://github.com/tonikelope/megabasterd/releases/latest" target="_blank"><b>Download latest build</b></a></h2>
<h3 align="center"><i>Note: MegaBasterd jar version requires <a href="https://adoptium.net/es/temurin/releases/?version=11" target="_blank">Java 11 or later</a> (at the moment it works in Java 8 but it is not guaranteed).</i></h3>
<p align="center"><a href="https://github.com/tonikelope/megabasterd/releases/latest" target="_blank"><img src="https://raw.githubusercontent.com/tonikelope/megabasterd/master/src/main/resources/images/linux-mac-windows.png"></a></p>
<p align="center"><a href="https://github.com/tonikelope/megabasterd/issues/397"><b>Would you like to help by translating MegaBasterd into your favorite language?</b></a></p>


![Screnshot](/src/main/resources/images/mbasterd_screen.png)




<p align="center"><a href="https://youtu.be/5TkBXT7osQI"><b>MegaBasterd DEMO</b></a></p>

<p align="center"><img src="https://raw.githubusercontent.com/tonikelope/megabasterd/master/coffee.png"><br><img src="https://raw.githubusercontent.com/tonikelope/megabasterd/master/src/main/resources/images/ethereum_toni.png"></p>

<p align="center"><a href="https://github.com/tonikelope/megabasterd/issues/385#issuecomment-1019215670">BONUS: Why the f*ck has MegaBasterd stopped downloading?</a></p>

<p align="center"><b>IMPORTANT:</b> You are not authorized to use MegaBasterd in any way that violates <a href="https://mega.io/es/terms"><b>MEGA's terms of use</b></a>.</p>

## Docker (browser-accessible UI)

This repository can be run in a Docker container and accessed from a browser via **noVNC** (the existing Swing UI is rendered in a virtual X server).

### Quick start (docker compose)

```bash
docker compose up --build
```

Then open:

- http://localhost:6080/vnc.html

Downloads and app configuration are persisted under:

- `./docker-data/downloads`
- `./docker-data/config`

### Notes

- noVNC is exposed **without authentication** in this setup. Only bind/publish it to trusted networks.
- If you change the container port mapping, update the URL accordingly.
- The container starts MegaBasterd with working directory `/downloads` so the default download folder `.` is persisted across restarts.

### SmartProxy + IKEv2 (inside Docker)

The Docker setup supports using **IKEv2 (IPsec) VPN tunnels** as SmartProxy entries.

- Compose must grant the container `NET_ADMIN` (and usually `NET_RAW`).
- If you run with `docker run` (not compose), you must also add these capabilities.
- Add IKEv2 lines to the SmartProxy custom list using:
	- `ikev2://username:password@hostname`
	- If your password contains `@` or `:`, use the alternate format:
		- `ikev2:hostname@BASE64(username):BASE64(password)`

MegaBasterd will establish the tunnel (via **strongSwan**) when that entry is selected.

### SmartProxy + WireGuard (inside Docker)

The Docker setup also supports using **WireGuard** tunnels as SmartProxy entries.

- Put your WireGuard configs under `./docker-data/wireguard` (mounted into the container as `/wireguard`).
- Any `*.conf` file in `/wireguard` is automatically added to the SmartProxy pool as:
	- `wireguard://<filename-without-.conf>`
- Compose must grant the container `NET_ADMIN` and access to `/dev/net/tun`.

Troubleshooting commands:
	- `docker exec megabasterd wg show`
	- `docker exec megabasterd ip route`

#### Running without compose (example)

```bash
docker run --name megabasterd --rm \
  -p 6080:6080 \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -v "./docker-data/config:/config" \
  -v "./docker-data/downloads:/downloads" \
  megabasterd
```

#### Troubleshooting

- If the tunnel fails to connect, strongSwan/charon logs are written to `/var/log/charon.log` inside the container.
- Useful commands:
	- `docker exec megabasterd ipsec statusall`
	- `docker exec megabasterd tail -n 200 /var/log/charon.log`
