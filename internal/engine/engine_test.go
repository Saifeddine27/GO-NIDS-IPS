package engine

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Saifeddine27/nids-go/internal/config"
	"github.com/Saifeddine27/nids-go/internal/parser"
)

type MockBlocker struct {
	BlockedIPs []string
}

func (m *MockBlocker) BlockIP(ip string, duration time.Duration) error {
	m.BlockedIPs = append(m.BlockedIPs, ip)
	return nil
}

func (m *MockBlocker) IsBlocked(ip string) bool {
	for _, blocked := range m.BlockedIPs {
		if blocked == ip {
			return true
		}
	}
	return false
}

func setupTestEngine() (*Engine, *MockBlocker) {
	mockBlocker := &MockBlocker{BlockedIPs: make([]string, 0)}
	cfg := config.DefaultConfig()
	eng := NewEngine(mockBlocker, cfg)
	return eng, mockBlocker
}

func TestSYNFlood(t *testing.T) {
	eng, mockBlocker := setupTestEngine()
	attackerIP := "10.0.0.99"

	for i := 0; i < 100; i++ {
		eng.Process(parser.NetworkEvent{
			IPSource: net.ParseIP(attackerIP),
			IPDest:   net.ParseIP("192.168.1.10"),
			Protocol: "TCP",
			IsSYN:    true,
		})
	}

	time.Sleep(50 * time.Millisecond)

	eng.mu.RLock()
	defer eng.mu.RUnlock()

	alertKey := attackerIP + "|SYN_FLOOD"
	if _, exists := eng.lastAlert[alertKey]; !exists {
		t.Errorf("L'alerte SYN_FLOOD n'a pas été déclenchée")
	}

	if !mockBlocker.IsBlocked(attackerIP) {
		t.Errorf("L'IP %s aurait dû être bloquée", attackerIP)
	}
}

func TestPortScan(t *testing.T) {
	eng, mockBlocker := setupTestEngine()
	attackerIP := "10.0.0.100"

	for i := 1; i <= 15; i++ {
		eng.Process(parser.NetworkEvent{
			IPSource: net.ParseIP(attackerIP),
			IPDest:   net.ParseIP("192.168.1.10"),
			Protocol: "TCP",
			DestPort: uint16(i),
		})
	}

	time.Sleep(50 * time.Millisecond)

	eng.mu.RLock()
	defer eng.mu.RUnlock()

	alertKey := attackerIP + "|PORT_SCAN|CRITICAL"
	if _, exists := eng.lastAlert[alertKey]; !exists {
		t.Errorf("L'alerte PORT_SCAN CRITICAL n'a pas été déclenchée")
	}

	if !mockBlocker.IsBlocked(attackerIP) {
		t.Errorf("L'IP %s aurait dû être bloquée", attackerIP)
	}
}

func TestPingSweep(t *testing.T) {
	eng, mockBlocker := setupTestEngine()
	attackerIP := "10.0.0.101"

	for i := 1; i <= 10; i++ {
		eng.DetectorPingSweep(parser.NetworkEvent{
			IPSource: net.ParseIP(attackerIP),
			IPDest:   net.ParseIP(fmt.Sprintf("192.168.1.%d", i)),
			Protocol: "ICMP",
		})
	}

	time.Sleep(50 * time.Millisecond)

	eng.mu.RLock()
	defer eng.mu.RUnlock()

	alertKey := attackerIP + "|PING_SWEEP|CRITICAL"
	if _, exists := eng.lastAlert[alertKey]; !exists {
		t.Errorf("L'alerte PING_SWEEP CRITICAL n'a pas été déclenchée")
	}

	if !mockBlocker.IsBlocked(attackerIP) {
		t.Errorf("L'IP %s aurait dû être bloquée", attackerIP)
	}
}

func TestBruteForce(t *testing.T) {
	eng, mockBlocker := setupTestEngine()
	attackerIP := "10.0.0.102"

	for i := 0; i < 20; i++ {
		eng.Process(parser.NetworkEvent{
			IPSource: net.ParseIP(attackerIP),
			IPDest:   net.ParseIP("192.168.1.10"),
			Protocol: "TCP",
			DestPort: 22, // SSH
		})
	}

	time.Sleep(50 * time.Millisecond)

	eng.mu.RLock()
	defer eng.mu.RUnlock()

	alertKey := attackerIP + "|BRUTE_FORCE_SSH"
	if _, exists := eng.lastAlert[alertKey]; !exists {
		t.Errorf("L'alerte BRUTE_FORCE_SSH n'a pas été déclenchée")
	}

	if !mockBlocker.IsBlocked(attackerIP) {
		t.Errorf("L'IP %s aurait dû être bloquée", attackerIP)
	}
}

func TestUDPFlood(t *testing.T) {
	eng, mockBlocker := setupTestEngine()
	attackerIP := "10.0.0.103"

	for i := 0; i < 200; i++ {
		eng.Process(parser.NetworkEvent{
			IPSource: net.ParseIP(attackerIP),
			IPDest:   net.ParseIP("192.168.1.10"),
			Protocol: "UDP",
			DestPort: 8080,
		})
	}

	time.Sleep(50 * time.Millisecond)

	eng.mu.RLock()
	defer eng.mu.RUnlock()

	alertKey := attackerIP + "|UDP_FLOOD"
	if _, exists := eng.lastAlert[alertKey]; !exists {
		t.Errorf("L'alerte UDP_FLOOD n'a pas été déclenchée")
	}

	if !mockBlocker.IsBlocked(attackerIP) {
		t.Errorf("L'IP %s aurait dû être bloquée", attackerIP)
	}
}

func TestNormalTraffic_NoAlert(t *testing.T) {
	eng, mockBlocker := setupTestEngine()
	normalIP := "10.0.0.200"

	// Envoyer du trafic sous tous les seuils
	// 2 ports différents (seuil port scan warning = 5)
	for i := 1; i <= 2; i++ {
		eng.Process(parser.NetworkEvent{
			IPSource: net.ParseIP(normalIP),
			IPDest:   net.ParseIP("192.168.1.10"),
			Protocol: "TCP",
			DestPort: uint16(i),
		})
	}

	// 5 paquets SYN sur le même port (seuil SYN flood = 100)
	for i := 0; i < 5; i++ {
		eng.Process(parser.NetworkEvent{
			IPSource: net.ParseIP(normalIP),
			IPDest:   net.ParseIP("192.168.1.10"),
			Protocol: "TCP",
			DestPort: 80,
			IsSYN:    true,
		})
	}

	// 10 paquets UDP sur le même port (seuil UDP flood = 200)
	for i := 0; i < 10; i++ {
		eng.Process(parser.NetworkEvent{
			IPSource: net.ParseIP(normalIP),
			IPDest:   net.ParseIP("192.168.1.10"),
			Protocol: "UDP",
			DestPort: 8080,
		})
	}

	eng.mu.RLock()
	defer eng.mu.RUnlock()

	// Aucune alerte ne doit exister
	for key := range eng.lastAlert {
		t.Errorf("Alerte inattendue pour du trafic normal : %s", key)
	}

	if mockBlocker.IsBlocked(normalIP) {
		t.Errorf("L'IP %s ne devrait pas être bloquée pour du trafic normal", normalIP)
	}
}

func TestPortScan_WarningOnly(t *testing.T) {
	eng, mockBlocker := setupTestEngine()
	attackerIP := "10.0.0.201"

	// 5 ports = seuil WARNING exactement, pas CRITICAL (seuil = 15)
	for i := 1; i <= 5; i++ {
		eng.Process(parser.NetworkEvent{
			IPSource: net.ParseIP(attackerIP),
			IPDest:   net.ParseIP("192.168.1.10"),
			Protocol: "TCP",
			DestPort: uint16(i),
		})
	}

	eng.mu.RLock()
	defer eng.mu.RUnlock()

	// Le WARNING doit exister
	warningKey := attackerIP + "|PORT_SCAN|WARNING"
	if _, exists := eng.lastAlert[warningKey]; !exists {
		t.Errorf("L'alerte PORT_SCAN WARNING n'a pas été déclenchée")
	}

	// Le CRITICAL ne doit PAS exister
	criticalKey := attackerIP + "|PORT_SCAN|CRITICAL"
	if _, exists := eng.lastAlert[criticalKey]; exists {
		t.Errorf("L'alerte PORT_SCAN CRITICAL ne devrait pas être déclenchée avec seulement 5 ports")
	}

	// L'IP ne doit PAS être bloquée (seul CRITICAL bloque)
	if mockBlocker.IsBlocked(attackerIP) {
		t.Errorf("L'IP %s ne devrait pas être bloquée pour un simple WARNING", attackerIP)
	}
}
