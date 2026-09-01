# dns-over-minecraft

Recursive DNS server over Minecraft network protocol (Java Edition).

![cli](docs/Screenshot_20260902_024432.png)

![real client](docs/Screenshot_20260902_024527.png)

Hides DNS queries inside real gaming protocol. Useful for censorship circumvention

**Server** accepts vanilla-like pings on `:25565`, decodes `serverAddress = base32(dnsWire)+".mc"` to a `dns.Msg`, resolves via priority-ordered upstreams (TCP/DoT/DoH) + 5m LRU cache + custom records, returns `base64(dnsWire)` in `description.text`.

**Client** is same binary: `dnsmc -S` = server, `dnsmc <name> <type>` = query.

## Quick start

```bash
go build -o dnsmc ./cmd/dnsmc
cp config.yaml.example config.yaml
./dnsmc -S -config config.yaml &
./dnsmc -server 127.0.0.1:25565 mybox.mc A        # custom record -> 10.0.0.5
./dnsmc -server 127.0.0.1:25565 example.com A     # upstream
```

## Config

See `config.yaml.example`. `priority` low = tried first (5 before 10 before 15). Fallback sequential.

## Protocol

Wire vanilla-identical: `Handshake(nextState=1) + StatusRequest`, suffix `.mc`, base32 query, base64 response in Status JSON.

## System service

See `deploy/dnsmc.service`.
