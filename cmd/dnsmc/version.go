package main

var (
	// version is stamped at build time via -ldflags "-X main.version=...".
	version = "dev"
	// commit is the source revision the binary was built from.
	commit = "none"
	// date is the UTC build time.
	date = "unknown"
)