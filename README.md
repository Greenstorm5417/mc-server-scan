# mc-scan

Scan IPv4 for Minecraft servers that have players online. SYN-scans port 25565
(or TCP-connects if you lack `CAP_NET_RAW`), then Server-List-Pings the hosts
that answer.

## Web UI (easiest)

Pushes to `main` publish `ghcr.io/greenstorm5417/mc-server-scan:latest`
via GitHub Actions. First pull may need a public package: GitHub →
Packages → Package settings → Change visibility.

```bash
docker compose pull
docker compose up
```

Or run the image directly:

```bash
docker run --rm -p 8080:8080 --cap-add NET_RAW --cap-add NET_ADMIN \
  ghcr.io/greenstorm5417/mc-server-scan:latest
```

To build locally instead of pulling:

```bash
docker compose up --build
```

Open http://127.0.0.1:8080, type a CIDR (`192.168.1.0/24`), tick **Include
private / reserved** for RFC1918, hit **Scan**. Hits stream into the table
and append to `data/servers.txt`.

Without Docker:

```bash
cargo run --release -- --listen 127.0.0.1:8080
```

The UI will not scan all of IPv4 just because you left the range blank. Name
the range.

## CLI

```bash
# LAN
cargo run --release -- --range 192.168.1.0/24 --include-reserved

# resume-aware internet scan (needs root / CAP_NET_RAW for SYN rate)
sudo ./target/x86_64-unknown-linux-musl/release/mc-scan
```

`--listen` still accepts the usual flags; they become the form defaults.

## Docker notes

- Bridge networking + published `8080` is the default. That is TCP-connect
  mode unless you also pass `--cap-add NET_RAW --cap-add NET_ADMIN`.
- For a real SYN scan out the host NIC, set `network_mode: host` in
  `compose.yaml` (UI then binds the host's `:8080`).
- State and hits live in `./data` (`mc-scan.state`, `servers.txt`).

Needs `CAP_NET_RAW` (root) to hit ~300k packets/s on a 250 Mbps link.
