package alert

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type AlertInfos struct {
	Time        time.Time `json:"time"`
	IpSrc       net.IP    `json:"ip_src"`
	AttaqueType string    `json:"attaque_type"`
	DegreAlert  string    `json:"degre_alert"`
	Description string    `json:"description"`
}

const maxLogSizeBytes = 10 * 1024 * 1024

var logMu sync.Mutex

func LogAlert(info *AlertInfos) {
	logMu.Lock()
	defer logMu.Unlock()

	const logFile = "alerts.json"

	if fi, err := os.Stat(logFile); err == nil && fi.Size() >= maxLogSizeBytes {
		rotated := fmt.Sprintf("alerts_%s.json", time.Now().Format("20060102_150405"))
		if err := os.Rename(logFile, rotated); err != nil {
			fmt.Printf("Erreur lors de la rotation du log : %v\n", err)
		}
	}

	flags := os.O_APPEND | os.O_CREATE | os.O_WRONLY
	file, err := os.OpenFile(logFile, flags, 0644)
	if err != nil {
		fmt.Printf("Erreur lors de l'ouverture du fichier : %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(info); err != nil {
		fmt.Printf("Erreur lors de l'encodage JSON : %v\n", err)
	}
}
