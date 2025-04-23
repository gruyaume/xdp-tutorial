package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/gruyaume/xdp-tutorial/internal/config"
	"github.com/gruyaume/xdp-tutorial/internal/pass"
)

func main() {
	configFilePath := flag.String("config", "", "The config file to be provided to the server")
	flag.Parse()
	if *configFilePath == "" {
		fmt.Println("Please provide a config file path using -config flag")
		return
	}
	config, err := config.Load(*configFilePath)
	if err != nil {
		fmt.Println("Error loading config:", err)
		return
	}
	iface, err := net.InterfaceByName(config.Interface)
	if err != nil {
		fmt.Println("Error getting interface:", err)
		return
	}

	program, err := pass.Load(iface)
	if err != nil {
		fmt.Println("Error loading pass XDP program:", err)
		return
	}

	defer program.Link.Close()
	defer program.Objs.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		bytes, err := program.Objs.GetBytesNumber(pass.XDP_PASS)
		if err != nil {
			log.Printf("Error getting bytes number (XDP_PASS): %v", err)
			continue
		}
		fmt.Println("Bytes number:", bytes)
		packets, err := program.Objs.GetPacketsNumber(pass.XDP_PASS)
		if err != nil {
			log.Printf("Error getting packets number (XDP_PASS): %v", err)
			continue
		}
		fmt.Println("Packets number:", packets)
	}

	select {}
}
