package filter

import (
	"net"

	"github.com/Saifeddine27/nids-go/internal/parser"
)

var noisePorts = map[uint16]bool{
	53:   true, // DNS
	67:   true, // DHCP server
	68:   true, // DHCP client
	123:  true, // NTP
	5353: true, // mDNS
	5355: true, // LLMNR
	1900: true, // SSDP
}
var whitelistedIPs = make(map[string]bool)

func AddWhitelistedIP(ip string) {
	whitelistedIPs[ip] = true
}

func IsAllowed(ne *parser.NetworkEvent) bool {

	if ne.IPSource == nil || ne.IPDest == nil {
		return false
	}

	if whitelistedIPs[ne.IPSource.String()] {
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
	return ip[0] >= 224 && ip[0] <= 239
}
