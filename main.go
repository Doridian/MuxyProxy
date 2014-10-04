package main

import (
	"log"
	"time"
)

var __DEBUG = true

func main() {
	config := LoadProtocols("protocols.json")
	listeners := LoadListeners("listeners.json", config, __DEBUG)
	log.Println("GO")
	listeners.Start()
	for {
		time.Sleep(10 * time.Minute)
	}
}
