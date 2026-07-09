package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Saifeddine27/nids-go/internal/capture"
	"github.com/Saifeddine27/nids-go/internal/engine"
	"github.com/Saifeddine27/nids-go/internal/filter"
	"github.com/Saifeddine27/nids-go/internal/ips" // Importation du module de prévention
	"github.com/Saifeddine27/nids-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Printf("Erreur fatale lors de la recherche des interfaces : %v\n", err)
		return
	}

	fmt.Println("🌐 Interfaces réseau disponibles :")

	for i, dev := range devices {
		desc := dev.Description
		if desc == "" {
			desc = "Aucune description"
		}
		fmt.Printf("  [%d] %s (%s)\n", i, dev.Name, desc)
	}

	fmt.Print("\n👉 Entrez le nom de l'interface à écouter (ex: eth0, lo, wlan0) ou 'any' pour toutes : ")
	reader := bufio.NewReader(os.Stdin)
	selectedInterface, _ := reader.ReadString('\n')
	selectedInterface = strings.TrimSpace(selectedInterface)

	if selectedInterface == "" {
		selectedInterface = "any"
	}

	fmt.Println("--------------------------------------------------")

	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ipString := ipnet.IP.String()
				fmt.Println(ipString)
				filter.AddWhitelistedIP(ipString)
			}
		}
	}

	blocker := ips.NewIPTablesBlocker()

	eng := engine.NewEngine(blocker)

	sniffer := capture.NewSniffer(selectedInterface)
	fmt.Println("Listening on:", sniffer.Interface)
	packetChan := make(chan gopacket.Packet)
	go sniffer.Start(packetChan)

	for packet := range packetChan {
		ne := parser.ParsePacket(packet)
		if ne == nil {
			continue
		}
		if filter.IsAllowed(ne) {
			if ne.Protocol == "TCP" || ne.Protocol == "UDP" {
				eng.Process(*ne)
			} else if ne.Protocol == "ICMP" {
				eng.DetectorPingSweep(*ne)
			}
		}
	}
}
