package mc

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
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
	// Passphrase, when non-empty, requires every client to prefix its server
	// address with "p.<passphrase>." (see extractPassphrase). A client without
	// the shared passphrase is treated like an unauthenticated Minecraft client.
	Passphrase string
	// RateLimit is the per-IP connection/queries-per-second budget; 0 disables.
	RateLimit int
	// MaxConnections caps concurrent accepted connections; 0 disables.
	MaxConnections int
	// MaxFrameSize caps inbound handshake/status/ping frame payloads; 0 uses
	// the default (4096).
	MaxFrameSize int

	fragments   *fragmentAssembler
	connSlots   chan struct{}
	rateLimiter *ipRateLimiter
}

const (
	defaultLogInterval = 30 * time.Second
	// handshakeBudget bounds how long a connection may take to send the
	// handshake + status request frames (slowloris defense).
	handshakeBudget = 2 * time.Second
	// defaultMaxFrameSize is the inbound frame payload ceiling when
	// Server.MaxFrameSize is zero.
	defaultMaxFrameSize = 4096
)

func (serverInstance *Server) ListenAndServe(requestContext context.Context) error {
	listener, err := net.Listen("tcp", serverInstance.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Printf("dnsmc server listening on %s (suffix=%q)", serverInstance.Addr, serverInstance.Suffix)
	serverInstance.fragments = newFragmentAssembler()

	if serverInstance.MaxConnections > 0 {
		serverInstance.connSlots = make(chan struct{}, serverInstance.MaxConnections)
	}
	if serverInstance.RateLimit > 0 {
		serverInstance.rateLimiter = newIPRateLimiter(serverInstance.RateLimit)
		go serverInstance.cleanupRateLimiter(requestContext)
	}

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
		if serverInstance.connSlots != nil {
			select {
			case serverInstance.connSlots <- struct{}{}:
			default:
				log.Printf("dnsmc server: rejecting connection from %s (max connections reached)", remoteIP(connection))
				go serverInstance.rejectAndClose(connection, false)
				continue
			}
		}
		go func() {
			if serverInstance.connSlots != nil {
				defer func() { <-serverInstance.connSlots }()
			}
			serverInstance.handleConn(connection)
		}()
	}
}

func (serverInstance *Server) cleanupRateLimiter(requestContext context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-requestContext.Done():
			return
		case <-ticker.C:
			serverInstance.rateLimiter.cleanup(5 * time.Minute)
		}
	}
}

func (serverInstance *Server) handleConn(connection net.Conn) {
	defer connection.Close()

	if serverInstance.rateLimiter != nil && !serverInstance.rateLimiter.Allow(remoteIP(connection)) {
		log.Printf("dnsmc server: rate limit exceeded for %s", connection.RemoteAddr())
		serverInstance.rejectAndClose(connection, false)
		return
	}
	_ = connection.SetDeadline(time.Now().Add(handshakeBudget))

	packetID, payload, err := ReadFrameLimit(connection, serverInstance.effectiveMaxFrameSize())
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

	packetID, payload, err = ReadFrameLimit(connection, serverInstance.effectiveMaxFrameSize())
	if err != nil {
		return
	}
	if packetID != 0x00 {
		return
	}
	_ = payload

	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

	bareAddress := dnscodec.StripSuffix(handshake.ServerAddress, serverInstance.Suffix)
	if serverInstance.Passphrase != "" {
		var authenticated bool
		bareAddress, authenticated = extractPassphrase(bareAddress, serverInstance.Passphrase)
		if !authenticated {
			log.Printf("dnsmc server: auth failed for %s (serverAddress=%q)", connection.RemoteAddr(), handshake.ServerAddress)
			serverInstance.rejectAndClose(connection, true)
			return
		}
	}
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
			serverInstance.sendDNSResponse(connection, errorResponse)
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
	serverInstance.sendDNSResponse(connection, responseMessage)
	serverInstance.handlePing(connection)
}

// defaultMOTD is shown in the status description when the server has none
// configured; it also keeps dnsmc clients from rejecting the response for an
// empty description.
const defaultMOTD = "dnsmc server"

func (serverInstance *Server) effectiveMOTD() string {
	if serverInstance.MOTD != "" {
		return serverInstance.MOTD
	}
	return defaultMOTD
}

// effectiveMaxFrameSize returns the inbound frame payload ceiling, defaulting to
// defaultMaxFrameSize when not configured.
func (serverInstance *Server) effectiveMaxFrameSize() int {
	if serverInstance.MaxFrameSize > 0 {
		return serverInstance.MaxFrameSize
	}
	return defaultMaxFrameSize
}

const passphraseMarker = "p."

// extractPassphrase verifies the "p.<passphrase>." prefix on a bare (suffix
// stripped) server address and returns the remainder on success. The comparison
// is constant-time so an observer cannot time-guess the passphrase.
func extractPassphrase(bareAddress, passphrase string) (string, bool) {
	if !strings.HasPrefix(bareAddress, passphraseMarker) {
		return "", false
	}
	remainder := bareAddress[len(passphraseMarker):]
	separatorIndex := strings.IndexByte(remainder, '.')
	if separatorIndex < 0 {
		return "", false
	}
	received := remainder[:separatorIndex]
	if subtle.ConstantTimeCompare([]byte(received), []byte(passphrase)) != 1 {
		return "", false
	}
	return remainder[separatorIndex+1:], true
}

// writeVanillaStatus replies as a normal Minecraft server (vanilla status JSON +
// ping) without resolving anything.
func (serverInstance *Server) writeVanillaStatus(connection net.Conn) {
	vanillaJSON := dnscodec.BuildVanillaStatusJSON(
		serverInstance.MOTD, serverInstance.VersionName, serverInstance.VersionProtocol,
		serverInstance.MaxPlayers, serverInstance.OnlinePlayers, serverInstance.Sample, serverInstance.Favicon,
	)
	_, _ = connection.Write(EncodeStatusResponseJSON(vanillaJSON))
	serverInstance.handlePing(connection)
}

// rejectAndClose answers an unauthorized/rate-limited/capped connection as if it
// had pinged a normal Minecraft server, then lets it close. When framesConsumed
// is false (no handshake read yet) it first drains the handshake + status
// request within the handshake budget so the reply is well-formed.
func (serverInstance *Server) rejectAndClose(connection net.Conn, framesConsumed bool) {
	defer connection.Close()
	if !framesConsumed {
		_ = connection.SetDeadline(time.Now().Add(handshakeBudget))
		if _, _, err := ReadFrameLimit(connection, serverInstance.effectiveMaxFrameSize()); err != nil {
			return
		}
		if _, _, err := ReadFrameLimit(connection, serverInstance.effectiveMaxFrameSize()); err != nil {
			return
		}
	}
	serverInstance.writeVanillaStatus(connection)
}

// sendDNSResponse encodes a DNS response into the compact favicon payload and
// writes the status JSON (description carrying the motd).
func (serverInstance *Server) sendDNSResponse(connection net.Conn, responseMessage *dns.Msg) {
	payloadBase64, err := dnscodec.EncodeResponse(responseMessage)
	if err != nil {
		payloadBase64, _ = dnscodec.EncodeResponse(dnscodec.BuildErrorResponse(responseMessage, 2))
	}
	serverInstance.writeStatusJSON(connection, dnscodec.BuildStatusJSON(serverInstance.effectiveMOTD(), payloadBase64))
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
		serverInstance.writeStatusJSON(connection, dnscodec.BuildStatusJSON(
			serverInstance.effectiveMOTD(), base64.StdEncoding.EncodeToString([]byte(fragmentAckMarker))))
		serverInstance.handlePing(connection)
		return
	}

	serverInstance.sendDNSResponse(connection, responseMessage)
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
	packetID, payload, err := ReadFrameLimit(connection, serverInstance.effectiveMaxFrameSize())
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
