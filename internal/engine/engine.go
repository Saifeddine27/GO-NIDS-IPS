package engine

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Saifeddine27/nids-go/internal/alert"
	"github.com/Saifeddine27/nids-go/internal/ips"
	"github.com/Saifeddine27/nids-go/internal/parser"
)

type Engine struct {
	mu            sync.RWMutex
	PortScanMem   map[string]map[uint16]time.Time
	ICMPMem       map[string]map[string]time.Time
	SYNMem        map[string][]time.Time
	BruteForceMem map[string]map[uint16][]time.Time
	UDPFloodMem   map[string][]time.Time
	lastAlert     map[string]time.Time
	blocker       ips.Blocker
}

func NewEngine(b ips.Blocker) *Engine {
	return &Engine{
		PortScanMem:   make(map[string]map[uint16]time.Time),
		ICMPMem:       make(map[string]map[string]time.Time),
		SYNMem:        make(map[string][]time.Time),
		BruteForceMem: make(map[string]map[uint16][]time.Time),
		UDPFloodMem:   make(map[string][]time.Time),
		lastAlert:     make(map[string]time.Time),
		blocker:       b,
	}
}

const alertCooldown = 10 * time.Second

func (e *Engine) shouldAlert(key string) bool {
	last, seen := e.lastAlert[key]
	if !seen || time.Since(last) >= alertCooldown {
		e.lastAlert[key] = time.Now()
		return true
	}
	return false
}

func (e *Engine) Process(ne parser.NetworkEvent) {
	now := time.Now()
	ip := ne.IPSource.String()
	e.mu.Lock()
	defer e.mu.Unlock()

	e.detectPortScan(ip, ne.DestPort, now)

	if ne.Protocol == "TCP" && ne.IsSYN {
		e.detectSYNFlood(ip, now)
	}

	bruteForcePorts := map[uint16]string{
		22:   "SSH",
		23:   "TELNET",
		21:   "FTP",
		3389: "RDP",
		5900: "VNC",
	}
	if service, ok := bruteForcePorts[ne.DestPort]; ok {
		e.detectBruteForce(ip, ne.DestPort, service, now)
	}

	if ne.Protocol == "UDP" {
		e.detectUDPFlood(ip, now)
	}
}

func (e *Engine) triggerPrevention(ip string) {
	if e.blocker != nil {
		go func() {
			if err := e.blocker.BlockIP(ip, 10*time.Minute); err != nil {
				fmt.Printf("[IPS ERREUR] Impossible d'exécuter l'action préventive sur %s: %v\n", ip, err)
			}
		}()
	}
}

func (e *Engine) detectPortScan(ip string, destPort uint16, now time.Time) {
	window := 10 * time.Second

	if _, exists := e.PortScanMem[ip]; !exists {
		e.PortScanMem[ip] = make(map[uint16]time.Time)
	}
	e.PortScanMem[ip][destPort] = now

	for port, t := range e.PortScanMem[ip] {
		if now.Sub(t) > window {
			delete(e.PortScanMem[ip], port)
		}
	}

	uniquePorts := len(e.PortScanMem[ip])

	if uniquePorts >= 15 {
		key := ip + "|PORT_SCAN|CRITICAL"
		if e.shouldAlert(key) {
			logAndPrint(&alert.AlertInfos{
				Time:        now,
				IpSrc:       net.ParseIP(ip),
				AttaqueType: "PORT_SCAN",
				DegreAlert:  "CRITICAL",
				Description: fmt.Sprintf("%d ports uniques ciblés en moins de 10s", uniquePorts),
			})
			e.triggerPrevention(ip)
		}
	} else if uniquePorts >= 5 {
		key := ip + "|PORT_SCAN|WARNING"
		if e.shouldAlert(key) {
			logAndPrint(&alert.AlertInfos{
				Time:        now,
				IpSrc:       net.ParseIP(ip),
				AttaqueType: "PORT_SCAN",
				DegreAlert:  "WARNING",
				Description: fmt.Sprintf("%d ports uniques ciblés en moins de 10s", uniquePorts),
			})
		}
	}
}

func (e *Engine) detectSYNFlood(ip string, now time.Time) {
	window := 5 * time.Second
	threshold := 100

	e.SYNMem[ip] = append(e.SYNMem[ip], now)

	cutoff := now.Add(-window)
	filtered := e.SYNMem[ip][:0]
	for _, t := range e.SYNMem[ip] {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	e.SYNMem[ip] = filtered

	if len(e.SYNMem[ip]) >= threshold {
		key := ip + "|SYN_FLOOD"
		if e.shouldAlert(key) {
			logAndPrint(&alert.AlertInfos{
				Time:        now,
				IpSrc:       net.ParseIP(ip),
				AttaqueType: "SYN_FLOOD",
				DegreAlert:  "CRITICAL",
				Description: fmt.Sprintf("%d paquets SYN en moins de 5s (possible SYN flood)", len(e.SYNMem[ip])),
			})
			e.triggerPrevention(ip)
		}
	}
}

func (e *Engine) detectBruteForce(ip string, port uint16, service string, now time.Time) {
	window := 30 * time.Second
	threshold := 20

	if _, exists := e.BruteForceMem[ip]; !exists {
		e.BruteForceMem[ip] = make(map[uint16][]time.Time)
	}
	e.BruteForceMem[ip][port] = append(e.BruteForceMem[ip][port], now)

	cutoff := now.Add(-window)
	filtered := e.BruteForceMem[ip][port][:0]
	for _, t := range e.BruteForceMem[ip][port] {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	e.BruteForceMem[ip][port] = filtered

	count := len(e.BruteForceMem[ip][port])
	if count >= threshold {
		key := fmt.Sprintf("%s|BRUTE_FORCE_%s", ip, service)
		if e.shouldAlert(key) {
			logAndPrint(&alert.AlertInfos{
				Time:        now,
				IpSrc:       net.ParseIP(ip),
				AttaqueType: "BRUTE_FORCE_" + service,
				DegreAlert:  "CRITICAL",
				Description: fmt.Sprintf("%d connexions vers %s (port %d) en 30s", count, service, port),
			})
			e.triggerPrevention(ip)
		}
	}
}

func (e *Engine) detectUDPFlood(ip string, now time.Time) {
	window := 5 * time.Second
	threshold := 200

	e.UDPFloodMem[ip] = append(e.UDPFloodMem[ip], now)

	cutoff := now.Add(-window)
	filtered := e.UDPFloodMem[ip][:0]
	for _, t := range e.UDPFloodMem[ip] {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	e.UDPFloodMem[ip] = filtered

	if len(e.UDPFloodMem[ip]) >= threshold {
		key := ip + "|UDP_FLOOD"
		if e.shouldAlert(key) {
			logAndPrint(&alert.AlertInfos{
				Time:        now,
				IpSrc:       net.ParseIP(ip),
				AttaqueType: "UDP_FLOOD",
				DegreAlert:  "CRITICAL",
				Description: fmt.Sprintf("%d paquets UDP en moins de 5s", len(e.UDPFloodMem[ip])),
			})
			e.triggerPrevention(ip)
		}
	}
}

func (e *Engine) DetectorPingSweep(ne parser.NetworkEvent) {
	window := 10 * time.Second
	now := time.Now()
	ipSrc := ne.IPSource.String()
	ipDst := ne.IPDest.String()

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.ICMPMem[ipSrc]; !exists {
		e.ICMPMem[ipSrc] = make(map[string]time.Time)
	}

	e.ICMPMem[ipSrc][ipDst] = now

	for dst, t := range e.ICMPMem[ipSrc] {
		if now.Sub(t) > window {
			delete(e.ICMPMem[ipSrc], dst)
		}
	}

	uniqueHosts := len(e.ICMPMem[ipSrc])

	if uniqueHosts >= 10 {
		key := ipSrc + "|PING_SWEEP|CRITICAL"
		if e.shouldAlert(key) {
			logAndPrint(&alert.AlertInfos{
				Time:        now,
				IpSrc:       net.ParseIP(ipSrc),
				AttaqueType: "PING_SWEEP",
				DegreAlert:  "CRITICAL",
				Description: fmt.Sprintf("%d hôtes uniques pingués en moins de 10s", uniqueHosts),
			})
			e.triggerPrevention(ipSrc)
		}
	} else if uniqueHosts >= 4 {
		key := ipSrc + "|PING_SWEEP|WARNING"
		if e.shouldAlert(key) {
			logAndPrint(&alert.AlertInfos{
				Time:        now,
				IpSrc:       net.ParseIP(ipSrc),
				AttaqueType: "PING_SWEEP",
				DegreAlert:  "WARNING",
				Description: fmt.Sprintf("%d hôtes uniques pingués en moins de 10s", uniqueHosts),
			})
		}
	}
}

func logAndPrint(a *alert.AlertInfos) {
	icon := "[-]"
	if a.DegreAlert == "CRITICAL" {
		icon = "[!]"
	}
	fmt.Printf("%s %s | %s | %s | %s\n", icon, a.DegreAlert, a.AttaqueType, a.IpSrc, a.Description)
	alert.LogAlert(a)
}
