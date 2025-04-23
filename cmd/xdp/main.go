package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/gruyaume/xdp-tutorial/internal/pass"
)

func main() {
	// configFilePath := flag.String("config", "", "The config file to be provided to the server")
	// flag.Parse()
	// if *configFilePath == "" {
	// 	fmt.Println("Please provide a config file path using -config flag")
	// 	return
	// }
	// config, err := config.Load(*configFilePath)
	// if err != nil {
	// 	fmt.Println("Error loading config:", err)
	// 	return
	// }
	ifaceNames := []string{"vethR1", "vethR2"}

	program, err := pass.Load(ifaceNames)
	if err != nil {
		fmt.Println("Error loading pass XDP program:", err)
		return
	}

	defer program.Links[0].Close()
	defer program.Links[1].Close()
	defer program.Objs.Close()

	log.Printf("Attached XDP program to iface %q", ifaceNames[0])
	log.Printf("Attached XDP program to iface %q", ifaceNames[1])
	log.Printf("Press Ctrl-C to exit and remove the program")

	r1Idx, err := net.InterfaceByName(ifaceNames[0])
	if err != nil {
		log.Printf("Error getting interface index for %s: %v", ifaceNames[0], err)
		return
	}
	r2Idx, err := net.InterfaceByName(ifaceNames[1])
	if err != nil {
		log.Printf("Error getting interface index for %s: %v", ifaceNames[1], err)
		return
	}

	err = program.Objs.UpdateRoute(&pass.RouteOpts{
		Prefixlen: 32,
		Dst:       net.ParseIP("10.1.0.1"),
		Ifindex:   uint32(r2Idx.Index),
		Gateway:   net.ParseIP("0.0.0.0"),
	})
	if err != nil {
		log.Printf("Error updating route: %v", err)
		return
	}

	err = program.Objs.UpdateRoute(&pass.RouteOpts{
		Prefixlen: 32,
		Dst:       net.ParseIP("10.0.0.1"),
		Ifindex:   uint32(r1Idx.Index),
		Gateway:   net.ParseIP("0.0.0.0"),
	})
	if err != nil {
		log.Printf("Error updating route: %v", err)
		return
	}
	// send to hostB (10.1.0.1) via vethR2
	// objs.UpdateRoute(32, net.ParseIP("10.1.0.1"), r2Idx, net.IPv4(0, 0, 0, 0))

	// // return path: send back to hostA (10.0.0.1) via vethR1
	// objs.UpdateRoute(32, net.ParseIP("10.0.0.1"), r1Idx, net.IPv4(0, 0, 0, 0))

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
		routes, err := program.Objs.ListRoutes()
		if err != nil {
			log.Printf("Error listing routes: %v", err)
			continue
		}
		for _, route := range routes {
			fmt.Printf("Route: %s/%d via %s\n", route.Dst, route.Prefixlen, route.Gateway)
		}
	}

	select {}
}
