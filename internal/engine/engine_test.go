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
