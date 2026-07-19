package ips

import (
	"fmt"
	"log"
	"os/exec"
	"time"
)

type Blocker interface {
	BlockIP(ip string, duration time.Duration) error
}

type IPTablesBlocker struct{}

func NewIPTablesBlocker() *IPTablesBlocker {
	return &IPTablesBlocker{}
}

func (b *IPTablesBlocker) BlockIP(ip string, duration time.Duration) error {
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
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

	log.Printf("[IPS] IP débloquée automatiquement : %s\n", ip)
}
