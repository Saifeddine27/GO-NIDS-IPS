package capture

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Sniffer struct {
	Interface string
	handle    *pcap.Handle
}

func NewSniffer(iface string) *Sniffer {
	return &Sniffer{
		Interface: iface,
	}
}

func (s *Sniffer) Start(packetChan chan gopacket.Packet) error {
	handle, err := pcap.OpenLive(s.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening interface %s: %w", s.Interface, err)
	}
	s.handle = handle
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packetChan <- packet
	}
	close(packetChan)
	return nil
}

func (s *Sniffer) Stop() {
	if s.handle != nil {
		s.handle.Close()
	}
}
