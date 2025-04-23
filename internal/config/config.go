package config

import (
	"net"
	"os"

	"gopkg.in/yaml.v2"
)

type RouteYaml struct {
	Dst       string `yaml:"destination"`
	Prefixlen uint32 `yaml:"prefixlen"`
	Interface string `yaml:"interface"`
	Gateway   string `yaml:"gateway"`
}

type NeighborYaml struct {
	IP  string `yaml:"ip"`
	Mac string `yaml:"mac"`
}

type ConfigYaml struct {
	Interfaces []string       `yaml:"interfaces"`
	Routes     []RouteYaml    `yaml:"routes"`
	Neighbors  []NeighborYaml `yaml:"neighbors"`
	LogLevel   string         `yaml:"log_level"`
}

type Route struct {
	Dst       string
	Prefixlen uint32
	Interface *net.Interface
	Gateway   string
}

type Neighbor struct {
	IP  string
	Mac string
}

type Config struct {
	Interfaces []*net.Interface
	Routes     []Route
	Neighbors  []Neighbor
	LogLevel   string
}

func Load(path string) (Config, error) {
	var configYaml ConfigYaml
	config := Config{}

	data, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	err = yaml.Unmarshal(data, &configYaml)
	if err != nil {
		return config, err
	}
	for _, ifaceName := range configYaml.Interfaces {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return config, err
		}
		config.Interfaces = append(config.Interfaces, iface)
	}
	for _, route := range configYaml.Routes {
		iface, err := net.InterfaceByName(route.Interface)
		if err != nil {
			return config, err
		}

		config.Routes = append(config.Routes, Route{
			Dst:       route.Dst,
			Prefixlen: route.Prefixlen,
			Interface: iface,
			Gateway:   route.Gateway,
		})
	}
	for _, neighbor := range configYaml.Neighbors {
		config.Neighbors = append(config.Neighbors, Neighbor{
			IP:  neighbor.IP,
			Mac: neighbor.Mac,
		})
	}
	config.LogLevel = configYaml.LogLevel

	return config, nil
}
