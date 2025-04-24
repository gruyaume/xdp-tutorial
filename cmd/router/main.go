package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/gruyaume/router/internal/config"
	l "github.com/gruyaume/router/internal/logger"
	"github.com/gruyaume/router/internal/router"
	"go.uber.org/zap"
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

	logger, err := l.NewLogger(config.LogLevel)
	if err != nil {
		fmt.Println("Error creating logger:", err)
		return
	}

	if err := Run(config, logger); err != nil {
		logger.Errorf("Error running router: %v", err)
		return
	}
	defer func() {
		if err := logger.Sync(); err != nil {
			fmt.Println("Error syncing logger:", err)
		}
	}()
}

func Run(config *config.Config, logger *zap.SugaredLogger) error {
	program, err := router.Load(config.Interfaces)
	if err != nil {
		return fmt.Errorf("error loading pass XDP program: %w", err)
	}

	for _, link := range program.Links {
		defer link.Close()
	}
	defer program.Objs.Close()

	logger.Infof("Attached XDP program to ifaces")
	logger.Infof("Press Ctrl-C to exit and remove the program")

	for _, route := range config.Routes {
		err = program.Objs.UpdateRoute(&router.RouteOpts{
			Prefixlen: route.Prefixlen,
			Dst:       net.ParseIP(route.Dst),
			Ifindex:   uint32(route.Interface.Index),
			Gateway:   net.ParseIP(route.Gateway),
		})
		if err != nil {
			return fmt.Errorf("error updating route %s/%d via %s: %w", route.Dst, route.Prefixlen, route.Gateway, err)
		}
		logger.Infof("updated route %s/%d via %s", route.Dst, route.Prefixlen, route.Gateway)
	}

	for _, iface := range config.Interfaces {
		err = program.Objs.UpdateInterface(iface)
		if err != nil {
			return fmt.Errorf("error updating interface %s: %w", iface.Name, err)
		}
		logger.Infof("updated interface %s", iface.Name)
	}

	for _, neighbor := range config.Neighbors {
		err = program.Objs.UpdateNeighbor(&router.NeighborOpts{
			IP:  neighbor.IP,
			MAC: neighbor.Mac,
		})
		if err != nil {
			return fmt.Errorf("error updating neighbor %s: %w", neighbor.IP, err)
		}
		logger.Infof("updated neighbor %s", neighbor.IP)
	}

	select {}
}
