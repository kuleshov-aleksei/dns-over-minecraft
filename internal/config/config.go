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
	Cache         CacheConfig    `yaml:"cache"`
	Upstreams     []Upstream     `yaml:"upstreams"`
	CustomRecords []CustomRecord `yaml:"customRecords"`
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
	Size        int           `yaml:"size"`
	TTL         time.Duration `yaml:"ttl"`
	NegativeTTL time.Duration `yaml:"negativeTtl"`
}

type Upstream struct {
	Name     string        `yaml:"name"`
	Type     string        `yaml:"type"` // tcp, dot, doh
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
		Upstreams: []Upstream{
			{Name: "1.1.1.1-tcp", Type: "tcp", Addr: "1.1.1.1:53", Priority: 5, Timeout: 2 * time.Second},
			{Name: "cloudflare-doh", Type: "doh", URL: "https://cloudflare-dns.com/dns-query", Priority: 10, Timeout: 2 * time.Second},
			{Name: "google-doh", Type: "doh", URL: "https://dns.google/dns-query", Priority: 15, Timeout: 2 * time.Second},
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		path = "config.yaml"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	// defaults for zero values
	if cfg.Listen == "" {
		cfg.Listen = ":25565"
	}
	if cfg.Server.MOTD == "" {
		cfg.Server.MOTD = "§aDNS over Minecraft §7| §fRecursive resolver"
	}
	if cfg.Server.VersionName == "" {
		cfg.Server.VersionName = "1.21.4"
	}
	if cfg.Server.VersionProtocol == 0 {
		cfg.Server.VersionProtocol = 769
	}
	if cfg.Server.MaxPlayers == 0 {
		cfg.Server.MaxPlayers = 20
	}
	if cfg.Server.Sample == nil {
		cfg.Server.Sample = []SamplePlayer{
			{Name: "§eDNS §7is §aready", ID: "00000000-0000-0000-0000-000000000001"},
		}
	}
	if cfg.Cache.TTL == 0 {
		cfg.Cache.TTL = 5 * time.Minute
	}
	if cfg.Cache.NegativeTTL == 0 {
		cfg.Cache.NegativeTTL = 30 * time.Second
	}
	if cfg.Cache.Size == 0 {
		cfg.Cache.Size = 2048
	}
	if cfg.Suffix == "" {
		// allow empty to mean no suffix; keep as is
	}
	return cfg, nil
}
