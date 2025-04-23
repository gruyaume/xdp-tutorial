package config

import (
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
}

type Route struct {
	Dst       string
	Prefixlen uint32
	Interface string
	Gateway   string
}

type Neighbor struct {
	IP  string
	Mac string
}

type Config struct {
	Interfaces []string
	Routes     []Route
	Neighbors  []Neighbor
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
	config.Interfaces = configYaml.Interfaces
	for _, route := range configYaml.Routes {
		config.Routes = append(config.Routes, Route{
			Dst:       route.Dst,
			Prefixlen: route.Prefixlen,
			Interface: route.Interface,
			Gateway:   route.Gateway,
		})
	}
	for _, neighbor := range configYaml.Neighbors {
		config.Neighbors = append(config.Neighbors, Neighbor{
			IP:  neighbor.IP,
			Mac: neighbor.Mac,
		})
	}

	return config, nil
}
