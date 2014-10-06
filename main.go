package main

import (
	"github.com/Doridian/MuxyProxy/listeners"
	"github.com/Doridian/MuxyProxy/protocols"
	"log"
	"time"
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
