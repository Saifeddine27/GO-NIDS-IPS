package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LogFile              string `yaml:"log_file"`
	AlertCooldownSeconds int    `yaml:"alert_cooldown_seconds"`

	PortScan struct {
		WindowSeconds     int `yaml:"window_seconds"`
		ThresholdWarning  int `yaml:"threshold_warning"`
		ThresholdCritical int `yaml:"threshold_critical"`
	} `yaml:"port_scan"`

	SYNFlood struct {
		WindowSeconds int `yaml:"window_seconds"`
		Threshold     int `yaml:"threshold"`
	} `yaml:"syn_flood"`

	BruteForce struct {
		WindowSeconds int `yaml:"window_seconds"`
		Threshold     int `yaml:"threshold"`
	} `yaml:"brute_force"`

	UDPFlood struct {
		WindowSeconds int `yaml:"window_seconds"`
		Threshold     int `yaml:"threshold"`
	} `yaml:"udp_flood"`

	PingSweep struct {
		WindowSeconds     int `yaml:"window_seconds"`
		ThresholdWarning  int `yaml:"threshold_warning"`
		ThresholdCritical int `yaml:"threshold_critical"`
	} `yaml:"ping_sweep"`
}

func DefaultConfig() *Config {
	cfg := &Config{
		LogFile:              "alerts.json",
		AlertCooldownSeconds: 10,
	}
	cfg.PortScan.WindowSeconds = 10
	cfg.PortScan.ThresholdWarning = 5
	cfg.PortScan.ThresholdCritical = 15

	cfg.SYNFlood.WindowSeconds = 5
	cfg.SYNFlood.Threshold = 100

	cfg.BruteForce.WindowSeconds = 30
	cfg.BruteForce.Threshold = 20

	cfg.UDPFlood.WindowSeconds = 5
	cfg.UDPFlood.Threshold = 200

	cfg.PingSweep.WindowSeconds = 10
	cfg.PingSweep.ThresholdWarning = 4
	cfg.PingSweep.ThresholdCritical = 10

	return cfg
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
