package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

type ConfigYaml struct {
	Interfaces []string `yaml:"interfaces"`
}

type Config struct {
	Interfaces []string
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
	return config, nil
}
