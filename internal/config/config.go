package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen        string         `yaml:"listen"`
	Suffix        string         `yaml:"suffix"`
	Server        ServerConfig   `yaml:"server"`
	Client        ClientConfig   `yaml:"client"`
	Cache         CacheConfig    `yaml:"cache"`
	Security      SecurityConfig `yaml:"security"`
	Logging       LoggingConfig  `yaml:"logging"`
	Upstreams     []Upstream     `yaml:"upstreams"`
	CustomRecords []CustomRecord `yaml:"customRecords"`
}

// SecurityConfig holds abuse-surface hardening knobs for the Minecraft port.
// A zero value disables each control: passphrase "" = no ACL, rateLimit 0 =
// unlimited, maxConnections 0 = unlimited, maxFrameSize 0 = default (4096).
type SecurityConfig struct {
	Passphrase     string `yaml:"passphrase"`
	RateLimit      int    `yaml:"rateLimit"`
	MaxConnections int    `yaml:"maxConnections"`
	MaxFrameSize   int    `yaml:"maxFrameSize"`
}

type ServerConfig struct {
	MOTD            string         `yaml:"motd"`
	VersionName     string         `yaml:"versionName"`
	VersionProtocol int            `yaml:"versionProtocol"`
	MaxPlayers      int            `yaml:"maxPlayers"`
	OnlinePlayers   int            `yaml:"onlinePlayers"`
	Sample          []SamplePlayer `yaml:"sample"`
	Favicon         string         `yaml:"favicon"`
}

type SamplePlayer struct {
	Name string `yaml:"name"`
	ID   string `yaml:"id"`
}

type CacheConfig struct {
	Disabled    bool          `yaml:"disabled"`
	Size        int           `yaml:"size"`
	TTL         time.Duration `yaml:"ttl"`
	NegativeTTL time.Duration `yaml:"negativeTtl"`
}

type ClientConfig struct {
	Listen     string       `yaml:"listen"`
	Suffix     string       `yaml:"suffix"`
	Servers    []string     `yaml:"servers"`
	Cache      CacheConfig  `yaml:"cache"`
	Passphrase string       `yaml:"passphrase"`
	VPNDNS     VPNDNSConfig `yaml:"vpnDNS"`
}

// VPNDNSConfig controls discovery of DNS servers from active VPN connections.
// VPN DNS discovery is always enabled; these knobs tune its behaviour only.
type VPNDNSConfig struct {
	// AllowFallbackToTunnel, when true (default), sends a query to the
	// Minecraft dnsmc servers when every VPN DNS server is unreachable. When
	// false the client returns SERVFAIL instead, so internal names never leak
	// to remote dnsmc servers during a VPN outage (at the cost of DNS failure
	// until the tunnel recovers).
	AllowFallbackToTunnel bool `yaml:"allowFallbackToTunnel"`
	// RefreshInterval is how often the active-VPN DNS snapshot is re-read from
	// NetworkManager (seconds). 0 uses the default of 5s.
	RefreshInterval int `yaml:"refreshInterval"`
}

type LoggingConfig struct {
	Queries     bool          `yaml:"queries"`
	Performance bool          `yaml:"performance"`
	Analytics   bool          `yaml:"analytics"`
	Interval    time.Duration `yaml:"interval"`
}

type Upstream struct {
	Name     string        `yaml:"name"`
	Type     string        `yaml:"type"`
	Addr     string        `yaml:"addr"`
	URL      string        `yaml:"url"`
	SNI      string        `yaml:"sni"`
	Priority int           `yaml:"priority"`
	Timeout  time.Duration `yaml:"timeout"`
}

type CustomRecord struct {
	Name   string   `yaml:"name"`
	Type   string   `yaml:"type"`
	TTL    uint32   `yaml:"ttl"`
	Values []string `yaml:"values"`
}

func Default() Config {
	return Config{
		Listen: ":25565",
		Suffix: ".mc",
		Server: ServerConfig{
			MOTD:            "§aDNS over Minecraft §7| §fRecursive resolver §7| §eAdd server with suffix .mc",
			VersionName:     "1.21.4",
			VersionProtocol: 769,
			MaxPlayers:      20,
			OnlinePlayers:   1,
			Sample: []SamplePlayer{
				{Name: "§eDNS §7is §aready", ID: "00000000-0000-0000-0000-000000000001"},
				{Name: "§7Query via §fbase32+§7.suffix §7in Server Address", ID: "00000000-0000-0000-0000-000000000002"},
			},
			Favicon: "",
		},
		Cache: CacheConfig{
			Size:        2048,
			TTL:         5 * time.Minute,
			NegativeTTL: 30 * time.Second,
		},
		Logging: LoggingConfig{
			Queries:     false,
			Performance: false,
			Analytics:   false,
			Interval:    30 * time.Second,
		},
		Security: SecurityConfig{
			Passphrase:     "",
			RateLimit:      100,
			MaxConnections: 1024,
			MaxFrameSize:   4096,
		},
		Client: ClientConfig{
			Listen:  "127.0.0.1:53",
			Servers: []string{"127.0.0.1:25565"},
			Cache: CacheConfig{
				Size:        2048,
				TTL:         5 * time.Minute,
				NegativeTTL: 30 * time.Second,
			},
			VPNDNS: VPNDNSConfig{
				AllowFallbackToTunnel: true,
				RefreshInterval:       5,
			},
		},
		Upstreams: []Upstream{
			{Name: "1.1.1.1-tcp", Type: "tcp", Addr: "1.1.1.1:53", Priority: 5, Timeout: 2 * time.Second},
			{Name: "cloudflare-doh", Type: "doh", URL: "https://cloudflare-dns.com/dns-query", Priority: 10, Timeout: 2 * time.Second},
			{Name: "google-doh", Type: "doh", URL: "https://dns.google/dns-query", Priority: 15, Timeout: 2 * time.Second},
		},
	}
}

func Load(configPath string) (Config, error) {
	configuration := Default()
	if configPath == "" {
		configPath = "config.yaml"
	}
	fileBytes, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return configuration, nil
		}
		return configuration, err
	}
	if err := yaml.Unmarshal(fileBytes, &configuration); err != nil {
		return configuration, err
	}
	if configuration.Listen == "" {
		configuration.Listen = ":25565"
	}
	if configuration.Server.MOTD == "" {
		configuration.Server.MOTD = "§aDNS over Minecraft §7| §fRecursive resolver"
	}
	if configuration.Server.VersionName == "" {
		configuration.Server.VersionName = "1.21.4"
	}
	if configuration.Server.VersionProtocol == 0 {
		configuration.Server.VersionProtocol = 769
	}
	if configuration.Server.MaxPlayers == 0 {
		configuration.Server.MaxPlayers = 20
	}
	if configuration.Server.Sample == nil {
		configuration.Server.Sample = []SamplePlayer{
			{Name: "§eDNS §7is §aready", ID: "00000000-0000-0000-0000-000000000001"},
		}
	}
	if configuration.Cache.TTL == 0 {
		configuration.Cache.TTL = 5 * time.Minute
	}
	if configuration.Cache.NegativeTTL == 0 {
		configuration.Cache.NegativeTTL = 30 * time.Second
	}
	if configuration.Cache.Size == 0 {
		configuration.Cache.Size = 2048
	}
	if configuration.Client.Listen == "" {
		configuration.Client.Listen = "127.0.0.1:53"
	}
	if len(configuration.Client.Servers) == 0 {
		configuration.Client.Servers = []string{"127.0.0.1:25565"}
	}
	if configuration.Client.Cache.TTL == 0 {
		configuration.Client.Cache.TTL = 5 * time.Minute
	}
	if configuration.Client.Cache.NegativeTTL == 0 {
		configuration.Client.Cache.NegativeTTL = 30 * time.Second
	}
	if configuration.Client.Cache.Size == 0 {
		configuration.Client.Cache.Size = 2048
	}
	if configuration.Client.VPNDNS.RefreshInterval == 0 {
		configuration.Client.VPNDNS.RefreshInterval = 5
	}
	if configuration.Logging.Interval == 0 {
		configuration.Logging.Interval = 30 * time.Second
	}
	if configuration.Security.RateLimit == 0 {
		configuration.Security.RateLimit = 100
	}
	if configuration.Security.MaxConnections == 0 {
		configuration.Security.MaxConnections = 1024
	}
	if configuration.Security.MaxFrameSize == 0 {
		configuration.Security.MaxFrameSize = 4096
	}
	return configuration, nil
}
