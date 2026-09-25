package filter

import (
	"net"
	"sync"

	"github.com/Saifeddine27/nids-go/internal/parser"
)

var noisePorts = map[uint16]bool{
	53:   true,
	67:   true,
	68:   true,
	123:  true,
	5353: true,
	5355: true,
	1900: true,
}
var whitelistedIPs = make(map[string]bool)
var whitelistMu sync.RWMutex

func AddWhitelistedIP(ip string) {
	whitelistMu.Lock()
	defer whitelistMu.Unlock()
	whitelistedIPs[ip] = true
}

func IsAllowed(ne *parser.NetworkEvent) bool {

	if ne.IPSource == nil || ne.IPDest == nil {
		return false
	}

	whitelistMu.RLock()
	isWhitelisted := whitelistedIPs[ne.IPSource.String()]
	whitelistMu.RUnlock()

	if isWhitelisted {
		return false
	}

	if ne.IPDest.Equal(net.IPv4bcast) {
		return false
	}

	if isMulticast(ne.IPDest) {
		return false
	}

	if noisePorts[ne.SourcePort] || noisePorts[ne.DestPort] {
		return false
	}

	return true
}

func isMulticast(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsMulticast()
}
