package ips

import (
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"
)

type Blocker interface {
	BlockIP(ip string, duration time.Duration) error
}

type IPTablesBlocker struct {
	blockedIPs map[string]bool
	mu         sync.Mutex
}

func NewIPTablesBlocker() *IPTablesBlocker {
	return &IPTablesBlocker{
		blockedIPs: make(map[string]bool),
	}
}

func (b *IPTablesBlocker) IsBlocked(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.blockedIPs[ip]
}

func (b *IPTablesBlocker) BlockIP(ip string, duration time.Duration) error {
	b.mu.Lock()
	if b.blockedIPs[ip] {
		b.mu.Unlock()
		return nil
	}
	b.blockedIPs[ip] = true
	b.mu.Unlock()

	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		b.mu.Lock()
		delete(b.blockedIPs, ip)
		b.mu.Unlock()
		return fmt.Errorf("impossible de bloquer l'IP %s via iptables: %v", ip, err)
	}

	log.Printf("[IPS] IP bannie avec succès : %s pour %v\n", ip, duration)

	go b.unblockAfter(ip, duration)

	return nil
}

func (b *IPTablesBlocker) unblockAfter(ip string, duration time.Duration) {
	time.Sleep(duration)

	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("[IPS ERREUR] Échec du déblocage automatique pour l'IP %s : %v\n", ip, err)
		return
	}

	b.mu.Lock()
	delete(b.blockedIPs, ip)
	b.mu.Unlock()

	log.Printf("[IPS] IP débloquée automatiquement : %s\n", ip)
}
