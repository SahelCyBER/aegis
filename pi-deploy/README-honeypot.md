# AEGIS Pi honeypot

`aegis_honeypot.py` is a stdlib-only HTTP decoy (fake WordPress login). Any
credential POST or probe of a sensitive path pushes the source IP to a firewall
agent (`POST /block`, with `force: true`) and reports the event to the AEGIS API.

## Roles

Recommended layout: keep the decoy off the box that enforces blocks.

- **Gateway Pi**: runs only `aegis-firewall.service` (`firewall-agent/`).
  It does not run the honeypot.
- **Honeypot Pi (isolated)**: runs just `aegis_honeypot.py`. Set
  `AEGIS_LOCAL_FW=http://<gateway-pi>:8765` so blocks are forwarded to the
  gateway agent, and `AEGIS_API_URL=http://<aegis-server>:8000` for events.
  Open the decoy port in its host firewall (`sudo ufw allow 8081/tcp`) and make
  sure it can reach the gateway agent on 8765 and the AEGIS API on 8000.

A single-Pi setup also works: run both on the gateway Pi and leave
`AEGIS_LOCAL_FW` at its default `http://127.0.0.1:8765`.

## Configuration

Secrets live in a root-only env file read by the unit (`EnvironmentFile`):

```
sudo install -m 600 -o root -g root /dev/stdin /etc/aegis/honeypot.env <<'ENV'
AEGIS_API_URL=http://192.0.2.10:8000
AEGIS_API_KEY=...
# Must match the agent's AEGIS_FIREWALL_SECRET.
AEGIS_FIREWALL_SECRET=...
# Gateway Pi's agent; omit on a single-Pi setup.
AEGIS_LOCAL_FW=http://192.0.2.20:8765
ENV
# systemd does not strip trailing "# ..." comments: keep them on their own line.
sudo systemctl restart aegis-honeypot
```

## Verify

```
journalctl -u aegis-honeypot -f
```

From an allowed test host that is NOT in a skipped range (loopback, RFC1918,
Tailscale are never blocked), hit a decoy path:

```
curl -i http://<honeypot>:8081/.env
```

Expect `blocked <ip> reason=GET /.env code=200` in the journal. A line with
`REJECTED http=401` means `AEGIS_FIREWALL_SECRET` is missing or wrong.
