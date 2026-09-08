package vpndns

import (
	"fmt"

	"github.com/godbus/dbus/v5"
)

const (
	nmService   = "org.freedesktop.NetworkManager"
	nmPath      = "/org/freedesktop/NetworkManager"
	nmIface     = "org.freedesktop.NetworkManager"
	activeIface = "org.freedesktop.NetworkManager.Connection.Active"
	ip4Iface    = "org.freedesktop.NetworkManager.IP4Config"
	ip6Iface    = "org.freedesktop.NetworkManager.IP6Config"
)

// nmStateActivated is the NetworkManager active-connection state value for a
// fully activated (connected) connection.
const nmStateActivated uint32 = 2

// NewNM builds a Provider that discovers active VPN DNS servers by reading
// NetworkManager's runtime state over D-Bus (read-only: ActiveConnections ->
// Ip4/Ip6Config.NameserverData). Only connections of type "wireguard" that are
// activated are considered. When bus is nil the shared system bus is used.
//
// The returned provider performs its first refresh in the background when Start
// is called, so constructing it never blocks. If the system bus or NetworkManager
// is unavailable the provider simply yields no servers and resolution falls back
// to the Minecraft path.
func NewNM(bus *dbus.Conn) (*pollingProvider, error) {
	if bus == nil {
		var err error
		bus, err = dbus.SystemBus()
		if err != nil {
			return nil, fmt.Errorf("system bus: %w", err)
		}
	}
	return newPollingProvider(func() ([]Server, error) {
		return fetchNMServers(bus)
	}), nil
}

// fetchNMServers reads the current active-connection list and returns the DNS
// servers of activated wireguard connections, ordered by DnsPriority.
func fetchNMServers(bus *dbus.Conn) ([]Server, error) {
	root := bus.Object(nmService, nmPath)
	activeProperty, err := root.GetProperty(nmIface + ".ActiveConnections")
	if err != nil {
		return nil, fmt.Errorf("read ActiveConnections: %w", err)
	}
	var activePaths []dbus.ObjectPath
	if err := activeProperty.Store(&activePaths); err != nil {
		return nil, fmt.Errorf("decode ActiveConnections: %w", err)
	}

	var sources []serverSource
	for _, activePath := range activePaths {
		activeObject := bus.Object(nmService, activePath)
		if found, ok := activeVpnServers(bus, activeObject); ok {
			sources = append(sources, found...)
		}
	}
	return buildServers(sources), nil
}

// activeVpnServers returns the DNS servers of one active connection if it is an
// activated wireguard connection, reporting whether the connection qualifies.
func activeVpnServers(bus *dbus.Conn, activeObject dbus.BusObject) ([]serverSource, bool) {
	typeProperty, err := activeObject.GetProperty(activeIface + ".Type")
	if err != nil {
		return nil, false
	}
	var connectionType string
	if err := typeProperty.Store(&connectionType); err != nil || connectionType != "wireguard" {
		return nil, false
	}

	stateProperty, err := activeObject.GetProperty(activeIface + ".State")
	if err != nil {
		return nil, false
	}
	var state uint32
	if err := stateProperty.Store(&state); err != nil || state != nmStateActivated {
		return nil, false
	}

	var sources []serverSource
	for _, config := range []struct{ property, iface string }{
		{activeIface + ".Ip4Config", ip4Iface},
		{activeIface + ".Ip6Config", ip6Iface},
	} {
		pathProperty, err := activeObject.GetProperty(config.property)
		if err != nil {
			continue
		}
		var configPath dbus.ObjectPath
		if err := pathProperty.Store(&configPath); err != nil || configPath == "/" {
			continue
		}
		sources = append(sources, configNameservers(bus, configPath, config.iface)...)
	}
	return sources, true
}

// configNameservers extracts the NameserverData of an IP configuration object.
func configNameservers(bus *dbus.Conn, configPath dbus.ObjectPath, iface string) []serverSource {
	configObject := bus.Object(nmService, configPath)

	priority := 0
	if priorityProperty, err := configObject.GetProperty(iface + ".DnsPriority"); err == nil {
		_ = priorityProperty.Store(&priority)
	}

	nameserversProperty, err := configObject.GetProperty(iface + ".NameserverData")
	if err != nil {
		return nil
	}
	var nameserverData []map[string]dbus.Variant
	if err := nameserversProperty.Store(&nameserverData); err != nil {
		return nil
	}

	var sources []serverSource
	for _, entry := range nameserverData {
		var address string
		addressVariant, ok := entry["address"]
		if !ok || addressVariant.Store(&address) != nil {
			continue
		}
		var port uint32
		if portVariant, ok := entry["port"]; ok {
			_ = portVariant.Store(&port)
		}
		sources = append(sources, serverSource{addr: address, port: port, priority: priority})
	}
	return sources
}
