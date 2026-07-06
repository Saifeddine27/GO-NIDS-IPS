package parser

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type NetworkEvent struct {
	IPSource   net.IP
	IPDest     net.IP
	Protocol   string
	SourcePort uint16
	DestPort   uint16
	Payload    []byte
	Length     int
	IsSYN      bool
}

func ParsePacket(packet gopacket.Packet) *NetworkEvent {
	ne := &NetworkEvent{
		Protocol: "UNKNOWN",
		Length:   packet.Metadata().Length,
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, ok := ipLayer.(*layers.IPv4)
		if ok {
			ne.IPSource = ip.SrcIP
			ne.IPDest = ip.DstIP
		}
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, ok := ipLayer.(*layers.IPv6)
		if ok {
			ne.IPSource = ip.SrcIP
			ne.IPDest = ip.DstIP
		}
	} else {
		return nil
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if ok {
			ne.Protocol = "TCP"
			ne.SourcePort = uint16(tcp.SrcPort)
			ne.DestPort = uint16(tcp.DstPort)
			ne.IsSYN = tcp.SYN && !tcp.ACK
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if ok {
			ne.Protocol = "UDP"
			ne.SourcePort = uint16(udp.SrcPort)
			ne.DestPort = uint16(udp.DstPort)
		}
	}

	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		_, ok := icmpLayer.(*layers.ICMPv4)
		if ok {
			ne.Protocol = "ICMP"
		}
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		_, ok := icmpLayer.(*layers.ICMPv6)
		if ok {
			ne.Protocol = "ICMP"
		}
	}

	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		ne.Payload = appLayer.Payload()
	}

	return ne
}
