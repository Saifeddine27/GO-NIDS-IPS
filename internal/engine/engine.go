package engine

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Saifeddine27/nids-go/internal/alert"
	"github.com/Saifeddine27/nids-go/internal/config"
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
	cfg           *config.Config
	stopChan      chan struct{}
}

func NewEngine(b ips.Blocker, cfg *config.Config) *Engine {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	e := &Engine{
		PortScanMem:   make(map[string]map[uint16]time.Time),
		ICMPMem:       make(map[string]map[string]time.Time),
		SYNMem:        make(map[string][]time.Time),
		BruteForceMem: make(map[string]map[uint16][]time.Time),
		UDPFloodMem:   make(map[string][]time.Time),
		lastAlert:     make(map[string]time.Time),
		blocker:       b,
		cfg:           cfg,
		stopChan:      make(chan struct{}),
	}
	go e.cleanupLoop()
	return e
}

func (e *Engine) shouldAlert(key string) bool {
	alertCooldown := time.Duration(e.cfg.AlertCooldownSeconds) * time.Second
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
	window := time.Duration(e.cfg.PortScan.WindowSeconds) * time.Second

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

	if uniquePorts >= e.cfg.PortScan.ThresholdCritical {
		key := ip + "|PORT_SCAN|CRITICAL"
		if e.shouldAlert(key) {
			logAndPrint(&alert.AlertInfos{
				Time:        now,
				IpSrc:       net.ParseIP(ip),
				AttaqueType: "PORT_SCAN",
				DegreAlert:  "CRITICAL",
				Description: fmt.Sprintf("%d ports uniques ciblés en moins de %ds", uniquePorts, e.cfg.PortScan.WindowSeconds),
			})
			e.triggerPrevention(ip)
		}
	} else if uniquePorts >= e.cfg.PortScan.ThresholdWarning {
		key := ip + "|PORT_SCAN|WARNING"
		if e.shouldAlert(key) {
			logAndPrint(&alert.AlertInfos{
				Time:        now,
				IpSrc:       net.ParseIP(ip),
				AttaqueType: "PORT_SCAN",
				DegreAlert:  "WARNING",
				Description: fmt.Sprintf("%d ports uniques ciblés en moins de %ds", uniquePorts, e.cfg.PortScan.WindowSeconds),
			})
		}
	}
}

func (e *Engine) detectSYNFlood(ip string, now time.Time) {
	window := time.Duration(e.cfg.SYNFlood.WindowSeconds) * time.Second
	threshold := e.cfg.SYNFlood.Threshold

	e.SYNMem[ip] = append(e.SYNMem[ip], now)

	cutoff := now.Add(-window)
	e.SYNMem[ip] = compactTimeSlice(e.SYNMem[ip], cutoff)

	if len(e.SYNMem[ip]) >= threshold {
		key := ip + "|SYN_FLOOD"
		if e.shouldAlert(key) {
			logAndPrint(&alert.AlertInfos{
				Time:        now,
				IpSrc:       net.ParseIP(ip),
				AttaqueType: "SYN_FLOOD",
				DegreAlert:  "CRITICAL",
				Description: fmt.Sprintf("%d paquets SYN en moins de %ds (possible SYN flood)", len(e.SYNMem[ip]), e.cfg.SYNFlood.WindowSeconds),
			})
			e.triggerPrevention(ip)
		}
	}
}

func (e *Engine) detectBruteForce(ip string, port uint16, service string, now time.Time) {
	window := time.Duration(e.cfg.BruteForce.WindowSeconds) * time.Second
	threshold := e.cfg.BruteForce.Threshold

	if _, exists := e.BruteForceMem[ip]; !exists {
		e.BruteForceMem[ip] = make(map[uint16][]time.Time)
	}
	e.BruteForceMem[ip][port] = append(e.BruteForceMem[ip][port], now)

	cutoff := now.Add(-window)
	e.BruteForceMem[ip][port] = compactTimeSlice(e.BruteForceMem[ip][port], cutoff)

	count := len(e.BruteForceMem[ip][port])
	if count >= threshold {
		key := fmt.Sprintf("%s|BRUTE_FORCE_%s", ip, service)
		if e.shouldAlert(key) {
			logAndPrint(&alert.AlertInfos{
				Time:        now,
				IpSrc:       net.ParseIP(ip),
				AttaqueType: "BRUTE_FORCE_" + service,
				DegreAlert:  "CRITICAL",
				Description: fmt.Sprintf("%d connexions vers %s (port %d) en %ds", count, service, port, e.cfg.BruteForce.WindowSeconds),
			})
			e.triggerPrevention(ip)
		}
	}
}

func (e *Engine) detectUDPFlood(ip string, now time.Time) {
	window := time.Duration(e.cfg.UDPFlood.WindowSeconds) * time.Second
	threshold := e.cfg.UDPFlood.Threshold

	e.UDPFloodMem[ip] = append(e.UDPFloodMem[ip], now)

	cutoff := now.Add(-window)
	e.UDPFloodMem[ip] = compactTimeSlice(e.UDPFloodMem[ip], cutoff)

	if len(e.UDPFloodMem[ip]) >= threshold {
		key := ip + "|UDP_FLOOD"
		if e.shouldAlert(key) {
			logAndPrint(&alert.AlertInfos{
				Time:        now,
				IpSrc:       net.ParseIP(ip),
				AttaqueType: "UDP_FLOOD",
				DegreAlert:  "CRITICAL",
				Description: fmt.Sprintf("%d paquets UDP en moins de %ds", len(e.UDPFloodMem[ip]), e.cfg.UDPFlood.WindowSeconds),
			})
			e.triggerPrevention(ip)
		}
	}
}

func (e *Engine) DetectorPingSweep(ne parser.NetworkEvent) {
	window := time.Duration(e.cfg.PingSweep.WindowSeconds) * time.Second
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

	if uniqueHosts >= e.cfg.PingSweep.ThresholdCritical {
		key := ipSrc + "|PING_SWEEP|CRITICAL"
		if e.shouldAlert(key) {
			logAndPrint(&alert.AlertInfos{
				Time:        now,
				IpSrc:       net.ParseIP(ipSrc),
				AttaqueType: "PING_SWEEP",
				DegreAlert:  "CRITICAL",
				Description: fmt.Sprintf("%d hôtes uniques pingués en moins de %ds", uniqueHosts, e.cfg.PingSweep.WindowSeconds),
			})
			e.triggerPrevention(ipSrc)
		}
	} else if uniqueHosts >= e.cfg.PingSweep.ThresholdWarning {
		key := ipSrc + "|PING_SWEEP|WARNING"
		if e.shouldAlert(key) {
			logAndPrint(&alert.AlertInfos{
				Time:        now,
				IpSrc:       net.ParseIP(ipSrc),
				AttaqueType: "PING_SWEEP",
				DegreAlert:  "WARNING",
				Description: fmt.Sprintf("%d hôtes uniques pingués en moins de %ds", uniqueHosts, e.cfg.PingSweep.WindowSeconds),
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

func (e *Engine) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.cleanupStaleEntries()
		case <-e.stopChan:
			return
		}
	}
}

func (e *Engine) cleanupStaleEntries() {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()

	// Cleanup PortScanMem
	portWindow := time.Duration(e.cfg.PortScan.WindowSeconds) * time.Second
	for ip, ports := range e.PortScanMem {
		for port, t := range ports {
			if now.Sub(t) > portWindow {
				delete(ports, port)
			}
		}
		if len(ports) == 0 {
			delete(e.PortScanMem, ip)
		}
	}

	// Cleanup ICMPMem
	pingWindow := time.Duration(e.cfg.PingSweep.WindowSeconds) * time.Second
	for ip, dests := range e.ICMPMem {
		for dst, t := range dests {
			if now.Sub(t) > pingWindow {
				delete(dests, dst)
			}
		}
		if len(dests) == 0 {
			delete(e.ICMPMem, ip)
		}
	}

	// Cleanup SYNMem
	synWindow := time.Duration(e.cfg.SYNFlood.WindowSeconds) * time.Second
	synCutoff := now.Add(-synWindow)
	for ip, times := range e.SYNMem {
		e.SYNMem[ip] = compactTimeSlice(times, synCutoff)
		if len(e.SYNMem[ip]) == 0 {
			delete(e.SYNMem, ip)
		}
	}

	// Cleanup BruteForceMem
	bfWindow := time.Duration(e.cfg.BruteForce.WindowSeconds) * time.Second
	bfCutoff := now.Add(-bfWindow)
	for ip, ports := range e.BruteForceMem {
		for port, times := range ports {
			ports[port] = compactTimeSlice(times, bfCutoff)
			if len(ports[port]) == 0 {
				delete(ports, port)
			}
		}
		if len(ports) == 0 {
			delete(e.BruteForceMem, ip)
		}
	}

	// Cleanup UDPFloodMem
	udpWindow := time.Duration(e.cfg.UDPFlood.WindowSeconds) * time.Second
	udpCutoff := now.Add(-udpWindow)
	for ip, times := range e.UDPFloodMem {
		e.UDPFloodMem[ip] = compactTimeSlice(times, udpCutoff)
		if len(e.UDPFloodMem[ip]) == 0 {
			delete(e.UDPFloodMem, ip)
		}
	}
}

func (e *Engine) Stop() {
	close(e.stopChan)
}

func compactTimeSlice(times []time.Time, cutoff time.Time) []time.Time {
	filtered := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}

	if len(filtered) < cap(times)/2 {
		compact := make([]time.Time, len(filtered))
		copy(compact, filtered)
		return compact
	}
	return filtered
}
