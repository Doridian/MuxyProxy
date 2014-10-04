package main

import (
	"log"
	"time"
)

func main() {
	log.Println("Loading protocols.json")
	config, err := LoadProtocols("protocols.json")
	if err != nil {
		log.Fatalf("Error: %v", err)
		return
	}
	log.Println("Loading listeners.json")
	listeners, err := LoadListeners("listeners.json", config)
	if err != nil {
		log.Fatalf("Error: %v", err)
		return
	}
	log.Println("Starting listeners")
	listeners.Start()
	for {
		time.Sleep(10 * time.Minute)
	}
}
