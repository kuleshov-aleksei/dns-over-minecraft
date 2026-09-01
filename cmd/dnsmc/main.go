package main

import (
	"context"
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
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n  dnsmc -S [-listen :25565] [-config config.yaml]  # server\n  dnsmc [options] <name> [type]                       # client query\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n  dnsmc example.com A\n  dnsmc -server 1.2.3.4:25565 mybox.mc A\n  dnsmc -S -config config.yaml\n")
	}
	flag.Parse()

	if *serverMode {
		runServer(*cfgPath, *listen, *suffix)
		return
	}

	// client mode
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
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

	// suffix for client: try config suffix else default .mc
	effSuffix := ".mc"
	if *suffix != "" {
		effSuffix = *suffix
	} else {
		if cfg, err := config.Load(*cfgPath); err == nil && cfg.Suffix != "" {
			effSuffix = cfg.Suffix
		}
	}

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
