package main

import (
	"log"
	"time"
)

var _DEBUG = true

func main() {
	config := LoadProtocols("protocols.json")
	listeners := LoadListeners("listeners.json", config)
	log.Println("GO")
	listeners.Start()
	for {
		time.Sleep(10 * time.Minute)
	}
}
