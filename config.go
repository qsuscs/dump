package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type config struct {
	Listen string
	Path   string
	Proxy  bool
}

func readConfig(filename string) (config, error) {
	var cfg config

	file, err := os.Open(filename)
	if err != nil {
		return cfg, fmt.Errorf("Error opening config file: %w", err)
	}
	defer file.Close()

	dec := json.NewDecoder(file)

	err = dec.Decode(&cfg)
	if err != nil {
		return cfg, fmt.Errorf("Error decoding config: %w", err)
	}

	return cfg, nil
}
