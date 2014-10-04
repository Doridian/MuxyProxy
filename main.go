package main

import (
	"log"
	"time"
)

func main() {
	log.Println("Loading protocols.json")
	config := LoadProtocols("protocols.json")
	if config == nil {
		return
	}
	log.Println("Loading listeners.json")
	listeners := LoadListeners("listeners.json", config)
	if listeners == nil {
		return
	}
	log.Println("Starting listeners")
	listeners.Start()
	for {
		time.Sleep(10 * time.Minute)
	}
}
