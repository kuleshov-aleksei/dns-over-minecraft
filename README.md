# dns-over-minecraft

Recursive DNS server over Minecraft network protocol (Java Edition).

![cli](docs/Screenshot_20260902_024432.png)

![real client](docs/Screenshot_20260902_024527.png)

Hides DNS queries inside real gaming protocol. Useful for censorship circumvention

**Server** accepts vanilla-like pings on `:25565`, decodes `serverAddress = base32(dnsWire)+".mc"` to a `dns.Msg`, resolves via priority-ordered upstreams (TCP/DoT/DoH) + 5m LRU cache + custom records, returns `base64(dnsWire)` in `description.text`.

**Client** is same binary: `dnsmc -S` = server, `dnsmc <name> <type>` = query, `dnsmc -C` = local DNS service.

## Quick start

```bash
go build -o dnsmc ./cmd/dnsmc
cp config.yaml.example config.yaml
./dnsmc -S -config config.yaml &
./dnsmc -server 127.0.0.1:25565 mybox.mc A        # custom record -> 10.0.0.5
./dnsmc -server 127.0.0.1:25565 example.com A     # upstream
```

## Local DNS service (client cache)

`dnsmc -C` runs a local DNS resolver (UDP+TCP, default `127.0.0.1:53`) that forwards
every query to the configured dnsmc servers over Minecraft, with an in-memory client
cache in front to cut round trips. Point `/etc/resolv.conf` at it (or use it as a
dns-over-https replacement):

```bash
cp config.client.yaml.example config.client.yaml
./dnsmc -C -config config.client.yaml   # needs root for :53, or set client.listen to a high port
dig @127.0.0.1 example.com A
```

Client settings live under the `client:` section in `config.client.yaml.example`
(`listen`, `servers`, `cache`). Queries rotate round-robin across the `servers`
list and fail over to the next server when one is unreachable (each failure is
logged). NXDOMAIN is not cached, neither on the client nor the server.

## Config

See `config.yaml.example`. `priority` low = tried first (5 before 10 before 15). Fallback sequential.
Server logging is off by default; enable per-category with `logging.queries`, `logging.performance` (RPS + cache hit/miss rate), or `logging.analytics` (top 10 domains, all-time + last interval), reported every `logging.interval`.

## Protocol

Wire vanilla-identical: `Handshake(nextState=1) + StatusRequest`, suffix `.mc`, base32 query, base64 response in Status JSON.

## System service

See `deploy/dnsmc.service` (server) and `deploy/dnsmc-client.service` (client).
