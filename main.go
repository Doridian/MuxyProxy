package main

import (
	"log"
	"time"
	"github.com/Doridian/MuxyProxy/protocols"
	"github.com/Doridian/MuxyProxy/listeners"
)

func main() {
	log.Println("Loading protocols.json")
	config, err := protocols.Load("protocols.json")
	if err != nil {
		log.Fatalf("Error: %v", err)
		return
	}
	log.Println("Loading listeners.json")
	listeners, err := listeners.Load("listeners.json", config)
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
