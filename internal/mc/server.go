package mc

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/dns-over-minecraft/dns-over-minecraft/internal/dnscodec"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/resolver"
	"github.com/miekg/dns"
)

type Server struct {
	Addr            string
	Suffix          string
	Resolver        *resolver.Resolver
	MOTD            string
	VersionName     string
	VersionProtocol int
	MaxPlayers      int
	OnlinePlayers   int
	Sample          []map[string]string
	Favicon         string
	LogQueries      bool
	LogPerformance  bool
	LogAnalytics    bool
	LogInterval     time.Duration
	fragments       *fragmentAssembler
}

const defaultLogInterval = 30 * time.Second

func (serverInstance *Server) ListenAndServe(requestContext context.Context) error {
	listener, err := net.Listen("tcp", serverInstance.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Printf("dnsmc server listening on %s (suffix=%q)", serverInstance.Addr, serverInstance.Suffix)
	serverInstance.fragments = newFragmentAssembler()

	go func() {
		<-requestContext.Done()
		listener.Close()
	}()

	if serverInstance.LogPerformance || serverInstance.LogAnalytics {
		reportInterval := serverInstance.LogInterval
		if reportInterval <= 0 {
			reportInterval = defaultLogInterval
		}
		go serverInstance.reportStats(requestContext, reportInterval)
	}

	for {
		connection, err := listener.Accept()
		if err != nil {
			select {
			case <-requestContext.Done():
				return nil
			default:
				log.Printf("accept error: %v", err)
				continue
			}
		}
		go serverInstance.handleConn(connection)
	}
}

func (serverInstance *Server) handleConn(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

	packetID, payload, err := ReadFrame(connection)
	if err != nil {
		return
	}
	if packetID != 0x00 {
		return
	}
	handshake, err := ParseHandshake(payload)
	if err != nil {
		return
	}
	if handshake.NextState != 1 {
		return
	}

	packetID, payload, err = ReadFrame(connection)
	if err != nil {
		return
	}
	if packetID != 0x00 {
		return
	}
	_ = payload

	bareAddress := dnscodec.StripSuffix(handshake.ServerAddress, serverInstance.Suffix)
	if serverInstance.isFragmented(handshake, bareAddress) {
		serverInstance.handleFragmentConnection(connection, handshake, bareAddress)
		return
	}
	queryMessage, err := dnscodec.DecodeQuery(bareAddress, "")
	if err != nil {
		hasSuffix := serverInstance.Suffix != "" && dnscodec.StripSuffix(handshake.ServerAddress, serverInstance.Suffix) != handshake.ServerAddress
		if hasSuffix {
			bareLength := len(dnscodec.StripSuffix(handshake.ServerAddress, serverInstance.Suffix))
			log.Printf("decode failed for DNS query %q (bare %d chars): %v -- hint: generate with 'dnsmc encode <name> [type]' (want base32(packed dns.Msg)+suffix)", handshake.ServerAddress, bareLength, err)
			errorResponse := dnscodec.BuildErrorResponse(nil, 1)
			base64Response, _ := dnscodec.EncodeResponse(errorResponse)
			rawJSON := dnscodec.BuildStatusJSON(base64Response)
			_, _ = connection.Write(EncodeStatusResponseJSON(rawJSON))
			serverInstance.handlePing(connection)
			return
		}
		log.Printf("vanilla ping from %s (serverAddress=%q)", connection.RemoteAddr(), handshake.ServerAddress)
		vanillaJSON := dnscodec.BuildVanillaStatusJSON(
			serverInstance.MOTD, serverInstance.VersionName, serverInstance.VersionProtocol,
			serverInstance.MaxPlayers, serverInstance.OnlinePlayers, serverInstance.Sample, serverInstance.Favicon,
		)
		_, _ = connection.Write(EncodeStatusResponseJSON(vanillaJSON))
		serverInstance.handlePing(connection)
		return
	}

	timeoutContext, cancelFunc := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancelFunc()
	queryStartTime := time.Now()
	responseMessage, err := serverInstance.Resolver.Resolve(timeoutContext, queryMessage)
	if err != nil {
		responseMessage = dnscodec.BuildErrorResponse(queryMessage, 2)
	}
	if serverInstance.LogQueries && len(queryMessage.Question) > 0 {
		question := queryMessage.Question[0]
		log.Printf("dnsmc server: query from %s: %s %s -> %s (%s)",
			connection.RemoteAddr(), question.Name, dns.TypeToString[question.Qtype],
			dns.RcodeToString[responseMessage.Rcode], time.Since(queryStartTime).Round(time.Microsecond))
	}
	base64Response, err := dnscodec.EncodeResponse(responseMessage)
	if err != nil {
		base64Response, _ = dnscodec.EncodeResponse(dnscodec.BuildErrorResponse(queryMessage, 2))
	}
	serverInstance.writeStatusJSON(connection, dnscodec.BuildStatusJSON(base64Response))
	serverInstance.handlePing(connection)
}

const fragmentAckMarker = "fragment-ack"

// isFragmented reports whether a handshake is one piece of a multi-ping
// fragmented query: address shape "n.<nonce>.<piece>.<suffix>" plus sane
// fragment index/total encoded in the handshake ServerPort.
func (serverInstance *Server) isFragmented(handshake *Handshake, bareAddress string) bool {
	if !strings.HasPrefix(bareAddress, "n.") {
		return false
	}
	parts := strings.Split(bareAddress, ".")
	if len(parts) < 3 || len(parts[1]) != 4 {
		return false
	}
	index := int(handshake.ServerPort >> 8)
	total := int(handshake.ServerPort & 0xFF)
	return index >= 1 && index <= total && total >= minFragmentPieces && total <= maxFragmentPieces
}

func (serverInstance *Server) handleFragmentConnection(connection net.Conn, handshake *Handshake, bareAddress string) {
	parts := strings.Split(bareAddress, ".")
	nonce := parts[1]
	piece := strings.Join(parts[2:], "")
	index := int(handshake.ServerPort >> 8)
	total := int(handshake.ServerPort & 0xFF)
	key := fragmentKey{clientIP: remoteIP(connection), nonce: nonce}

	set, completer := serverInstance.fragments.add(key, index, total, piece)

	var responseMessage *dns.Msg
	switch {
	case completer:
		bareQuery := set.reassemble()
		queryMessage, decodeErr := dnscodec.DecodeQuery(bareQuery, "")
		if decodeErr != nil || serverInstance.Resolver == nil {
			responseMessage = dnscodec.BuildErrorResponse(nil, 2)
			set.storeResult(responseMessage, decodeErr)
			break
		}
		var resolveErr error
		timeoutContext, cancelFunc := context.WithTimeout(context.Background(), 4*time.Second)
		responseMessage, resolveErr = serverInstance.Resolver.Resolve(timeoutContext, queryMessage)
		cancelFunc()
		if resolveErr != nil {
			responseMessage = dnscodec.BuildErrorResponse(queryMessage, 2)
		}
		if serverInstance.LogQueries && len(queryMessage.Question) > 0 {
			question := queryMessage.Question[0]
			log.Printf("dnsmc server: fragment query from %s: %s %s -> %s (%d frags)",
				connection.RemoteAddr(), question.Name, dns.TypeToString[question.Qtype],
				dns.RcodeToString[responseMessage.Rcode], total)
		}
		set.storeResult(responseMessage, resolveErr)
	case index == total:
		var waitErr error
		responseMessage, waitErr = set.waitResult()
		if waitErr != nil {
			responseMessage = dnscodec.BuildErrorResponse(nil, 2)
		}
	default:
		serverInstance.writeStatusJSON(connection, dnscodec.BuildStatusJSON(fragmentAckMarker))
		serverInstance.handlePing(connection)
		return
	}

	base64Response, _ := dnscodec.EncodeResponse(responseMessage)
	serverInstance.writeStatusJSON(connection, dnscodec.BuildStatusJSON(base64Response))
	serverInstance.handlePing(connection)
}

func (serverInstance *Server) writeStatusJSON(connection net.Conn, rawJSON []byte) {
	var jsonRawMessage json.RawMessage
	if json.Unmarshal(rawJSON, &jsonRawMessage) != nil {
		log.Printf("invalid json generated")
		return
	}
	if _, err := connection.Write(EncodeStatusResponseJSON(rawJSON)); err != nil {
		return
	}
}

func remoteIP(connection net.Conn) string {
	if tcpAddress, ok := connection.RemoteAddr().(*net.TCPAddr); ok {
		return tcpAddress.IP.String()
	}
	return connection.RemoteAddr().String()
}

func (serverInstance *Server) handlePing(connection net.Conn) {
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	packetID, payload, err := ReadFrame(connection)
	if err != nil {
		return
	}
	if packetID == 0x01 {
		timestamp, err := DecodePing(payload)
		if err != nil {
			return
		}
		_, _ = connection.Write(EncodePong(timestamp))
	}
}

func (serverInstance *Server) reportStats(requestContext context.Context, reportInterval time.Duration) {
	if serverInstance.Resolver == nil {
		return
	}
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()
	for {
		select {
		case <-requestContext.Done():
			return
		case <-ticker.C:
			snapshot := serverInstance.Resolver.TakeWindow()
			if snapshot.Total == 0 {
				continue
			}
			if serverInstance.LogPerformance {
				log.Printf("dnsmc server: %s", formatPerformance(snapshot.Total, snapshot.CacheHits, snapshot.CacheMisses, reportInterval))
			}
			if serverInstance.LogAnalytics {
				allTime, lastWindow := serverInstance.Resolver.DomainStats(10)
				log.Printf("dnsmc server: %s", formatTopDomains(allTime, lastWindow, reportInterval))
			}
		}
	}
}

func formatPerformance(total int64, cacheHits, cacheMisses int64, window time.Duration) string {
	requestsPerSecond := float64(total) / window.Seconds()
	hitRate := 100.0 * float64(cacheHits) / float64(total)
	missRate := 100.0 * float64(cacheMisses) / float64(total)
	return fmt.Sprintf("performance: %d queries in %s (%.2f rps), cache hit %.1f%% miss %.1f%%",
		total, window.Round(time.Second), requestsPerSecond, hitRate, missRate)
}

func formatTopDomains(allTime, lastWindow []resolver.DomainCount, window time.Duration) string {
	return fmt.Sprintf("top domains: all-time [%s] | last %s [%s]",
		formatDomainList(allTime), window.Round(time.Second), formatDomainList(lastWindow))
}

func formatDomainList(domainCounts []resolver.DomainCount) string {
	if len(domainCounts) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(domainCounts))
	for _, domainCount := range domainCounts {
		parts = append(parts, fmt.Sprintf("%s (%d)", domainCount.Name, domainCount.Count))
	}
	return strings.Join(parts, ", ")
}
