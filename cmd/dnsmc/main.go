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
		serverMode     = flag.Bool("S", false, "run as server")
		listenAddress  = flag.String("listen", "", "listen addr (server mode)")
		configPath     = flag.String("config", "config.yaml", "config file path")
		suffixOverride = flag.String("suffix", "", "suffix override (e.g. .mc)")
		serverAddress  = flag.String("server", "127.0.0.1:25565", "server addr for client query")
		ipFlag         = flag.String("ip", "127.0.0.1", "IP for hosts command")
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
		runServer(*configPath, *listenAddress, *suffixOverride)
		return
	}

	arguments := flag.Args()
	if len(arguments) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	switch strings.ToLower(arguments[0]) {
	case "encode":
		runEncode(arguments[1:], *configPath, *suffixOverride)
		return
	case "decode":
		runDecode(arguments[1:])
		return
	case "hosts":
		runHosts(arguments[1:], *configPath, *suffixOverride, *ipFlag)
		return
	}

	domainName := arguments[0]
	queryTypeString := "A"
	if len(arguments) > 1 {
		queryTypeString = arguments[1]
	}
	queryType, exists := dns.StringToType[strings.ToUpper(queryTypeString)]
	if !exists {
		log.Fatalf("unknown qtype %q", queryTypeString)
	}

	effectiveSuffix := effectiveSuffix(*configPath, *suffixOverride)

	queryMessage := new(dns.Msg)
	queryMessage.SetQuestion(dns.Fqdn(domainName), queryType)
	queryMessage.RecursionDesired = true

	responseMessage, err := mc.Query(*serverAddress, effectiveSuffix, queryMessage)
	if err != nil {
		log.Fatalf("query failed: %v", err)
	}
	fmt.Printf(";; response: %s\n", dns.RcodeToString[responseMessage.Rcode])
	for _, resourceRecord := range responseMessage.Answer {
		fmt.Println(resourceRecord.String())
	}
	if len(responseMessage.Answer) == 0 {
		fmt.Println(";; no answer")
		if len(responseMessage.Ns) > 0 {
			fmt.Println(";; authority:")
			for _, resourceRecord := range responseMessage.Ns {
				fmt.Println(resourceRecord.String())
			}
		}
	}
}

func effectiveSuffix(configPath, suffixOverride string) string {
	if suffixOverride != "" {
		return suffixOverride
	}
	if loadedConfig, err := config.Load(configPath); err == nil && loadedConfig.Suffix != "" {
		return loadedConfig.Suffix
	}
	return ".mc"
}

func runEncode(arguments []string, configPath, suffixOverride string) {
	if len(arguments) == 0 {
		log.Fatalf("encode usage: dnsmc encode <name> [type]")
	}
	domainName := arguments[0]
	queryTypeString := "A"
	if len(arguments) > 1 {
		queryTypeString = arguments[1]
	}
	queryType, exists := dns.StringToType[strings.ToUpper(queryTypeString)]
	if !exists {
		log.Fatalf("unknown qtype %q", queryTypeString)
	}
	effectiveSuffix := effectiveSuffix(configPath, suffixOverride)
	queryMessage := new(dns.Msg)
	queryMessage.SetQuestion(dns.Fqdn(domainName), queryType)
	queryMessage.RecursionDesired = true
	queryMessage.Id = 0
	encodedQuery, err := dnscodec.EncodeQuery(queryMessage)
	if err != nil {
		log.Fatalf("encode: %v", err)
	}
	fullAddress := encodedQuery + effectiveSuffix
	chunkedAddress := chunkBase32(encodedQuery) + effectiveSuffix
	fmt.Printf("bare:    %s\n", encodedQuery)
	fmt.Printf("full:    %s\n", fullAddress)
	if chunkedAddress != fullAddress {
		fmt.Printf("chunked: %s  (labels <=63, use if full >63 per label)\n", chunkedAddress)
	}
	fmt.Printf("hosts:   127.0.0.1  %s\n", fullAddress)
	fmt.Printf("len:     %d (bare) + %d (suffix) = %d / 255 max ServerAddress\n", len(encodedQuery), len(effectiveSuffix), len(fullAddress))
	if len(fullAddress) > 255 {
		fmt.Printf("WARN: exceeds 255 char ServerAddress limit, query will fail with FORMERR\n")
	}
	if len(encodedQuery) > 63 && !strings.Contains(encodedQuery, ".") {
		fmt.Printf("NOTE: bare >63 chars, some resolvers/hosts may reject single label. Use chunked form.\n")
	}
}

func runHosts(arguments []string, configPath, suffixOverride, ipAddress string) {
	if len(arguments) == 0 {
		log.Fatalf("hosts usage: dnsmc hosts <name> [type]")
	}
	domainName := arguments[0]
	queryTypeString := "A"
	if len(arguments) > 1 {
		queryTypeString = arguments[1]
	}
	queryType, exists := dns.StringToType[strings.ToUpper(queryTypeString)]
	if !exists {
		log.Fatalf("unknown qtype %q", queryTypeString)
	}
	effectiveSuffix := effectiveSuffix(configPath, suffixOverride)
	queryMessage := new(dns.Msg)
	queryMessage.SetQuestion(dns.Fqdn(domainName), queryType)
	queryMessage.RecursionDesired = true
	queryMessage.Id = 0
	encodedQuery, err := dnscodec.EncodeQuery(queryMessage)
	if err != nil {
		log.Fatalf("encode: %v", err)
	}
	fullAddress := encodedQuery + effectiveSuffix
	fmt.Printf("%s  %s\n", ipAddress, fullAddress)
}

func chunkBase32(encodedQuery string) string {
	if len(encodedQuery) <= 63 {
		return encodedQuery
	}
	var parts []string
	for len(encodedQuery) > 63 {
		parts = append(parts, encodedQuery[:63])
		encodedQuery = encodedQuery[63:]
	}
	parts = append(parts, encodedQuery)
	return strings.Join(parts, ".")
}

func isBase32Like(input string) bool {
	normalizedInput := strings.TrimSpace(input)
	normalizedInput = strings.TrimSuffix(strings.ToLower(normalizedInput), ".mc")
	normalizedInput = strings.ReplaceAll(normalizedInput, ".", "")
	if normalizedInput == "" {
		return false
	}
	for _, character := range normalizedInput {
		if (character >= 'a' && character <= 'z') || (character >= '2' && character <= '7') {
			continue
		}
		return false
	}
	return true
}

func runDecode(arguments []string) {
	if len(arguments) == 0 {
		log.Fatalf("decode usage: dnsmc decode <base64>")
	}
	rawInput := strings.Join(arguments, "")
	rawInput = strings.TrimSpace(strings.Trim(rawInput, "\"'"))
	if strings.Contains(rawInput, "{") {
		var jsonMap map[string]interface{}
		if err := json.Unmarshal([]byte(rawInput), &jsonMap); err == nil {
			if descriptionMap, exists := jsonMap["description"].(map[string]interface{}); exists {
				if textValue, exists := descriptionMap["text"].(string); exists && textValue != "" {
					rawInput = textValue
				}
			}
		}
	}
	isBase32Input := isBase32Like(rawInput)
	if isBase32Input {
		if decodedQuery, err := dnscodec.DecodeQuery(rawInput, ""); err == nil {
			fmt.Printf(";; decoded as QUERY (base32) not response - you pasted the ServerAddress, not description.text:\n")
			fmt.Printf(";; question: %s\n", decodedQuery.Question[0].String())
			fmt.Printf("%s\n", decodedQuery.String())
			return
		} else {
			if strings.Contains(err.Error(), "wire too short") {
				log.Fatalf("decode: not a response, looks like an invalid query (base32) %q: %v\nHint: 'm5xw6z3mmuxgg33n' is 10 bytes wire (want >=12). Generate correct hosts entry with: dnsmc encode <name> [type]", rawInput, err)
			}
		}
	}
	decodedResponse, err := dnscodec.DecodeResponse(rawInput)
	if err != nil {
		if queryErr, _ := dnscodec.DecodeQuery(rawInput, ""); queryErr != nil {
			log.Fatalf("decode: response base64 error: %v (input len %d); also not valid query: %v\nHint: for vanilla simulation, 'encode' gives ServerAddress to put in /etc/hosts; 'decode' expects base64 from Server List description.text, not the hostname.", err, len(rawInput), queryErr)
		}
		log.Fatalf("decode: %v (input len %d)", err, len(rawInput))
	}
	fmt.Printf(";; response: %s\n", dns.RcodeToString[decodedResponse.Rcode])
	fmt.Printf("%s\n", decodedResponse.String())
	for _, resourceRecord := range decodedResponse.Answer {
		fmt.Println(resourceRecord.String())
	}
	for _, resourceRecord := range decodedResponse.Ns {
		fmt.Println(resourceRecord.String())
	}
	for _, resourceRecord := range decodedResponse.Extra {
		fmt.Println(resourceRecord.String())
	}
}

func runServer(configPath, listenOverride, suffixOverride string) {
	loadedConfig, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("config load: %v", err)
	}
	if listenOverride != "" {
		loadedConfig.Listen = listenOverride
	}
	if suffixOverride != "" {
		loadedConfig.Suffix = suffixOverride
	}

	cacheStore := cache.New(loadedConfig.Cache.Size, loadedConfig.Cache.TTL, loadedConfig.Cache.NegativeTTL)

	var customRecords []records.Record
	for _, customRecord := range loadedConfig.CustomRecords {
		customRecords = append(customRecords, records.Record{Name: customRecord.Name, Type: customRecord.Type, TTL: customRecord.TTL, Values: customRecord.Values})
	}
	recordStore, _ := records.New(customRecords)

	var upstreamList []upstream.Upstream
	for _, upstreamConfig := range loadedConfig.Upstreams {
		timeoutDuration := upstreamConfig.Timeout
		if timeoutDuration == 0 {
			timeoutDuration = 2 * time.Second
		}
		switch strings.ToLower(upstreamConfig.Type) {
		case "tcp":
			address := upstreamConfig.Addr
			if address == "" {
				address = "8.8.8.8:53"
			}
			upstreamList = append(upstreamList, upstream.NewTCP(upstreamConfig.Name, address, upstreamConfig.Priority, timeoutDuration))
		case "dot":
			address := upstreamConfig.Addr
			if address == "" {
				address = "1.1.1.1:853"
			}
			upstreamList = append(upstreamList, upstream.NewDoT(upstreamConfig.Name, address, upstreamConfig.SNI, upstreamConfig.Priority, timeoutDuration))
		case "doh":
			url := upstreamConfig.URL
			if url == "" {
				url = "https://cloudflare-dns.com/dns-query"
			}
			upstreamList = append(upstreamList, upstream.NewDoH(upstreamConfig.Name, url, upstreamConfig.Priority, timeoutDuration))
		default:
			log.Printf("unknown upstream type %q for %q, skipping", upstreamConfig.Type, upstreamConfig.Name)
		}
	}
	upstreamPool := upstream.NewPool(upstreamList)
	log.Printf("upstreams (priority order):")
	for _, upstreamInstance := range upstreamPool.List() {
		log.Printf("  %d %s", upstreamInstance.Priority(), upstreamInstance.Name())
	}

	resolverInstance := resolver.New(cacheStore, recordStore, upstreamPool)
	var sampleEntries []map[string]string
	for _, samplePlayer := range loadedConfig.Server.Sample {
		sampleEntries = append(sampleEntries, map[string]string{"name": samplePlayer.Name, "id": samplePlayer.ID})
	}
	minecraftServer := &mc.Server{
		Addr:            loadedConfig.Listen,
		Suffix:          loadedConfig.Suffix,
		Resolver:        resolverInstance,
		MOTD:            loadedConfig.Server.MOTD,
		VersionName:     loadedConfig.Server.VersionName,
		VersionProtocol: loadedConfig.Server.VersionProtocol,
		MaxPlayers:      loadedConfig.Server.MaxPlayers,
		OnlinePlayers:   loadedConfig.Server.OnlinePlayers,
		Sample:          sampleEntries,
		Favicon:         loadedConfig.Server.Favicon,
	}

	requestContext, cancelFunc := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelFunc()

	if err := minecraftServer.ListenAndServe(requestContext); err != nil {
		log.Fatalf("server: %v", err)
	}
}
