# dns-over-minecraft

Recursive DNS server over Minecraft network protocol (Java Edition).

![cli](docs/Screenshot_20260902_024432.png)

![real client](docs/Screenshot_20260902_024527.png)

Hides DNS queries inside real gaming protocol. Useful for censorship circumvention

**Server** accepts vanilla-like pings on `:25565`, decodes `serverAddress = base32(dnsWire)+".mc"` to a `dns.Msg`, resolves via priority-ordered upstreams (TCP/DoT/DoH) + 5m LRU cache + custom records, returns a compact owner-dropped response payload base64-encoded inside the status **favicon** (`data:image/png;base64,...`), with `description.text` showing the configured MOTD so the status looks like a normal Minecraft server.

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
logged). NXDOMAIN is not cached, neither on the client nor the server. To make
the client forward every query to a server (useful when testing server stats),
set `client.cache.disabled: true`.

## Test load

`make load` sends a light stream of `dig` queries to a running client service
(default `127.0.0.1:5300`) that forwards to your server — handy for watching
`logging.performance`/`logging.analytics`. It assumes the server and client
service are already running (e.g. `make run-server` and
`make client-service CLIENT_LISTEN=127.0.0.1:5300`), and with
`client.cache.disabled: true` repeated domains reach the server and build up
cache hits. Override with `RESOLVER=`, `PORT=`, `QUERIES=`, `DELAY=`.

## Config

See `config.yaml.example`. `priority` high - tried first (15 before 10 before 5). Fallback sequential.
Server logging is off by default; enable per-category with `logging.queries`, `logging.performance` (RPS + cache hit/miss rate), or `logging.analytics` (top 10 domains, all-time + last interval), reported every `logging.interval`.

## Protocol

Wire vanilla-identical: `Handshake(nextState=1) + StatusRequest`, suffix `.mc`, base32 query, compact base64 response in the Status JSON favicon.

The query wire is versioned: v1 (`0xFF` magic) has no EDNS; v2 (`0xFE` magic) adds a 1-byte
EDNS buffer-size field so the client's advertised size travels end-to-end. `0xFF` queries still
decode. DNSSEC (DO/CD) is intentionally not propagated. Upstreams always receive an EDNS 4096
request (or the client's size) so large responses aren't truncated; a truncated answer is retried
once with a 65535 buffer and never cached. The OPT pseudo-record is stripped from responses to
clients that sent none.

Queries whose encoded address would exceed 255 chars are **auto-fragmented**: the base32 query is
split across multiple handshake/status connections (`n.<nonce>.<piece>.<suffix>`, index/total
encoded in the handshake port), reassembled server-side, and answered on the final fragment.

Responses always ride in the status **favicon** (`data:image/png;base64,<payload>`) while
`description.text` shows the configured MOTD, so the status looks like a normal Minecraft server
to packet analysis. The payload is a compact owner-dropped wire ("dropping the owner", cf.
Cloudflare's 1.1.1.1 cache post): `0xD1` magic + uvarint rcode + flags + section counts; the
question name is a literal and RR owners collapse to a qname / previous-owner / table-index token
(an answer under the queried name costs one byte per record), with RDATA copied verbatim from an
uncompressed pack. This removes any practical size ceiling on responses.

## System service

See `deploy/dnsmc.service` (server) and `deploy/dnsmc-client.service` (client).
