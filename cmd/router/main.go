package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/gruyaume/router/internal/config"
	l "github.com/gruyaume/router/internal/logger"
	"github.com/gruyaume/router/internal/router"
	"github.com/gruyaume/router/version"
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

	program, err := router.Load(config.Interfaces)
	if err != nil {
		logger.Fatal("Error loading pass XDP program", zap.Error(err))
	}

	for _, link := range program.Links {
		defer link.Close()
	}
	defer program.Objs.Close()

	logger.Info("Attached XDP program to ifaces")
	logger.Info("Press Ctrl-C to exit and remove the program")

	for _, route := range config.Routes {
		err = program.Objs.UpdateRoute(&router.RouteOpts{
			Prefixlen: route.Prefixlen,
			Dst:       net.ParseIP(route.Dst),
			Ifindex:   uint32(route.Interface.Index),
			Gateway:   net.ParseIP(route.Gateway),
		})
		if err != nil {
			logger.Fatal("Error updating route", zap.String("dst", route.Dst), zap.Uint32("prefixlen", route.Prefixlen), zap.String("gateway", route.Gateway), zap.Error(err))
		}
		logger.Info("Updated route", zap.String("dst", route.Dst), zap.Uint32("prefixlen", route.Prefixlen), zap.String("gateway", route.Gateway), zap.String("interface", route.Interface.Name))
	}

	for _, iface := range config.Interfaces {
		err = program.Objs.UpdateInterface(iface)
		if err != nil {
			logger.Fatal("Error updating interface", zap.String("interface", iface.Name), zap.Error(err))
		}
		logger.Info("Updated interface", zap.String("interface", iface.Name))
	}

	for _, neighbor := range config.Neighbors {
		err = program.Objs.UpdateNeighbor(&router.NeighborOpts{
			IP:  neighbor.IP,
			MAC: neighbor.Mac,
		})
		if err != nil {
			logger.Fatal("Error updating neighbor", zap.String("ip", neighbor.IP), zap.Error(err))
		}
		logger.Info("Updated neighbor", zap.String("ip", neighbor.IP), zap.String("mac", neighbor.Mac))
	}

	v := version.GetVersion()
	logger.Info("Started Router", zap.String("version", v))
	select {}
}
