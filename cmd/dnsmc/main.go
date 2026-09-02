package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dns-over-minecraft/dns-over-minecraft/internal/cache"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/config"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/dnscodec"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/mc"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/records"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/resolver"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/upstream"
	"github.com/miekg/dns"
)

func main() {
	var (
		serverMode = flag.Bool("S", false, "run as server")
		listen     = flag.String("listen", "", "listen addr (server mode)")
		cfgPath    = flag.String("config", "config.yaml", "config file path")
		suffix     = flag.String("suffix", "", "suffix override (e.g. .mc)")
		serverAddr = flag.String("server", "127.0.0.1:25565", "server addr for client query")
		ipFlag     = flag.String("ip", "127.0.0.1", "IP for hosts command")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage:
  dnsmc -S [-listen :25565] [-config config.yaml]              # server
  dnsmc [options] <name> [type]                               # client query
  dnsmc encode <name> [type] [-suffix .mc]                    # print base32 for /etc/hosts + vanilla
  dnsmc decode <base64>                                       # decode description.text from vanilla ping
  dnsmc hosts <name> [type] [-ip 127.0.0.1] [-suffix .mc]      # print /etc/hosts line
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  dnsmc example.com A
  dnsmc -server 1.2.3.4:25565 example.com.mc A
  dnsmc -S -config config.yaml
  dnsmc encode example.com A          # -> m5xw...mc
  # add that .mc name as Server Address in Minecraft, refresh Server List, copy description.text
  dnsmc decode <base64-from-MOTD>
`)
	}
	flag.Parse()

	if *serverMode {
		runServer(*cfgPath, *listen, *suffix)
		return
	}

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// helper subcommands
	switch strings.ToLower(args[0]) {
	case "encode":
		runEncode(args[1:], *cfgPath, *suffix)
		return
	case "decode":
		runDecode(args[1:])
		return
	case "hosts":
		runHosts(args[1:], *cfgPath, *suffix, *ipFlag)
		return
	}

	// client mode: <name> [type]
	name := args[0]
	qtypeStr := "A"
	if len(args) > 1 {
		qtypeStr = args[1]
	}
	qtype, ok := dns.StringToType[strings.ToUpper(qtypeStr)]
	if !ok {
		log.Fatalf("unknown qtype %q", qtypeStr)
	}

	// suffix for client: try config suffix else default .mc
	effSuffix := effectiveSuffix(*cfgPath, *suffix)

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.RecursionDesired = true

	resp, err := mc.Query(*serverAddr, effSuffix, q)
	if err != nil {
		log.Fatalf("query failed: %v", err)
	}
	fmt.Printf(";; response: %s\n", dns.RcodeToString[resp.Rcode])
	for _, rr := range resp.Answer {
		fmt.Println(rr.String())
	}
	if len(resp.Answer) == 0 {
		fmt.Println(";; no answer")
		if len(resp.Ns) > 0 {
			fmt.Println(";; authority:")
			for _, rr := range resp.Ns {
				fmt.Println(rr.String())
			}
		}
	}
}

func effectiveSuffix(cfgPath, suffixOverride string) string {
	if suffixOverride != "" {
		return suffixOverride
	}
	if cfg, err := config.Load(cfgPath); err == nil && cfg.Suffix != "" {
		return cfg.Suffix
	}
	return ".mc"
}

func runEncode(args []string, cfgPath, suffixOverride string) {
	if len(args) == 0 {
		log.Fatalf("encode usage: dnsmc encode <name> [type]")
	}
	name := args[0]
	qtypeStr := "A"
	if len(args) > 1 {
		qtypeStr = args[1]
	}
	qtype, ok := dns.StringToType[strings.ToUpper(qtypeStr)]
	if !ok {
		log.Fatalf("unknown qtype %q", qtypeStr)
	}
	effSuffix := effectiveSuffix(cfgPath, suffixOverride)
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.RecursionDesired = true
	q.Id = 0
	enc, err := dnscodec.EncodeQuery(q)
	if err != nil {
		log.Fatalf("encode: %v", err)
	}
	full := enc + effSuffix
	// dotted chunking for labels >63
	chunked := chunkBase32(enc) + effSuffix
	fmt.Printf("bare:    %s\n", enc)
	fmt.Printf("full:    %s\n", full)
	if chunked != full {
		fmt.Printf("chunked: %s  (labels <=63, use if full >63 per label)\n", chunked)
	}
	fmt.Printf("hosts:   127.0.0.1  %s\n", full)
	fmt.Printf("len:     %d (bare) + %d (suffix) = %d / 255 max ServerAddress\n", len(enc), len(effSuffix), len(full))
	if len(full) > 255 {
		fmt.Printf("WARN: exceeds 255 char ServerAddress limit, query will fail with FORMERR\n")
	}
	if len(enc) > 63 && !strings.Contains(enc, ".") {
		fmt.Printf("NOTE: bare >63 chars, some resolvers/hosts may reject single label. Use chunked form.\n")
	}
}

func runHosts(args []string, cfgPath, suffixOverride, ip string) {
	if len(args) == 0 {
		log.Fatalf("hosts usage: dnsmc hosts <name> [type]")
	}
	name := args[0]
	qtypeStr := "A"
	if len(args) > 1 {
		qtypeStr = args[1]
	}
	qtype, ok := dns.StringToType[strings.ToUpper(qtypeStr)]
	if !ok {
		log.Fatalf("unknown qtype %q", qtypeStr)
	}
	effSuffix := effectiveSuffix(cfgPath, suffixOverride)
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.RecursionDesired = true
	q.Id = 0
	enc, err := dnscodec.EncodeQuery(q)
	if err != nil {
		log.Fatalf("encode: %v", err)
	}
	full := enc + effSuffix
	fmt.Printf("%s  %s\n", ip, full)
}

func chunkBase32(enc string) string {
	if len(enc) <= 63 {
		return enc
	}
	var parts []string
	for len(enc) > 63 {
		parts = append(parts, enc[:63])
		enc = enc[63:]
	}
	parts = append(parts, enc)
	return strings.Join(parts, ".")
}

func isBase32Like(s string) bool {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(strings.ToLower(s), ".mc")
	s = strings.ReplaceAll(s, ".", "")
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '2' && r <= '7') {
			continue
		}
		return false
	}
	return true
}

func runDecode(args []string) {
	if len(args) == 0 {
		log.Fatalf("decode usage: dnsmc decode <base64>")
	}
	// allow base64 with or without surrounding whitespace/quotes
	raw := strings.Join(args, "")
	raw = strings.TrimSpace(strings.Trim(raw, "\"'"))
	// also handle full JSON {"description":{"text":"..."}}
	if strings.Contains(raw, "{") {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &m); err == nil {
			if d, ok := m["description"].(map[string]interface{}); ok {
				if t, ok := d["text"].(string); ok && t != "" {
					raw = t
				}
			}
		}
	}
	// Heuristic: if input looks like base32 query (only A-Z2-7 + dots), treat as query
	isB32Like := isBase32Like(raw)
	if isB32Like {
		if q, errQ := dnscodec.DecodeQuery(raw, ""); errQ == nil {
			fmt.Printf(";; decoded as QUERY (base32) not response - you pasted the ServerAddress, not description.text:\n")
			fmt.Printf(";; question: %s\n", q.Question[0].String())
			fmt.Printf("%s\n", q.String())
			return
		} else {
			// Wire too short is the exact user error from /etc/hosts
			if strings.Contains(errQ.Error(), "wire too short") {
				log.Fatalf("decode: not a response, looks like an invalid query (base32) %q: %v\nHint: 'm5xw6z3mmuxgg33n' is 10 bytes wire (want >=12). Generate correct hosts entry with: dnsmc encode <name> [type]", raw, errQ)
			}
		}
	}
	msg, err := dnscodec.DecodeResponse(raw)
	if err != nil {
		if qErr, _ := dnscodec.DecodeQuery(raw, ""); qErr != nil {
			log.Fatalf("decode: response base64 error: %v (input len %d); also not valid query: %v\nHint: for vanilla simulation, 'encode' gives ServerAddress to put in /etc/hosts; 'decode' expects base64 from Server List description.text, not the hostname.", err, len(raw), qErr)
		}
		log.Fatalf("decode: %v (input len %d)", err, len(raw))
	}
	fmt.Printf(";; response: %s\n", dns.RcodeToString[msg.Rcode])
	fmt.Printf("%s\n", msg.String())
	for _, rr := range msg.Answer {
		fmt.Println(rr.String())
	}
	for _, rr := range msg.Ns {
		fmt.Println(rr.String())
	}
	for _, rr := range msg.Extra {
		fmt.Println(rr.String())
	}
}

func runServer(cfgPath, listenOverride, suffixOverride string) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config load: %v", err)
	}
	if listenOverride != "" {
		cfg.Listen = listenOverride
	}
	if suffixOverride != "" {
		cfg.Suffix = suffixOverride
	}

	// Build cache
	c := cache.New(cfg.Cache.Size, cfg.Cache.TTL, cfg.Cache.NegativeTTL)

	// Build records
	var recs []records.Record
	for _, cr := range cfg.CustomRecords {
		recs = append(recs, records.Record{Name: cr.Name, Type: cr.Type, TTL: cr.TTL, Values: cr.Values})
	}
	store, _ := records.New(recs)

	// Build upstream pool
	var ups []upstream.Upstream
	for _, u := range cfg.Upstreams {
		timeout := u.Timeout
		if timeout == 0 {
			timeout = 2 * time.Second
		}
		switch strings.ToLower(u.Type) {
		case "tcp":
			addr := u.Addr
			if addr == "" {
				addr = "8.8.8.8:53"
			}
			ups = append(ups, upstream.NewTCP(u.Name, addr, u.Priority, timeout))
		case "dot":
			addr := u.Addr
			if addr == "" {
				addr = "1.1.1.1:853"
			}
			ups = append(ups, upstream.NewDoT(u.Name, addr, u.SNI, u.Priority, timeout))
		case "doh":
			url := u.URL
			if url == "" {
				url = "https://cloudflare-dns.com/dns-query"
			}
			ups = append(ups, upstream.NewDoH(u.Name, url, u.Priority, timeout))
		default:
			log.Printf("unknown upstream type %q for %q, skipping", u.Type, u.Name)
		}
	}
	pool := upstream.NewPool(ups)
	log.Printf("upstreams (priority order):")
	for _, u := range pool.List() {
		log.Printf("  %d %s", u.Priority(), u.Name())
	}

	res := resolver.New(c, store, pool)
	var sample []map[string]string
	for _, sp := range cfg.Server.Sample {
		sample = append(sample, map[string]string{"name": sp.Name, "id": sp.ID})
	}
	srv := &mc.Server{
		Addr:            cfg.Listen,
		Suffix:          cfg.Suffix,
		Resolver:        res,
		MOTD:            cfg.Server.MOTD,
		VersionName:     cfg.Server.VersionName,
		VersionProtocol: cfg.Server.VersionProtocol,
		MaxPlayers:      cfg.Server.MaxPlayers,
		OnlinePlayers:   cfg.Server.OnlinePlayers,
		Sample:          sample,
		Favicon:         cfg.Server.Favicon,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := srv.ListenAndServe(ctx); err != nil {
		log.Fatalf("server: %v", err)
	}
}
