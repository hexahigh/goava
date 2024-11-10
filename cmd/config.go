package cmd

import (
	"os"
	"path"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var configDefaults = map[string]interface{}{
	"verbosity":              4,
	"config-dir":             getDefaultConfigDir(),
	"config-file":            "config.toml",
	"output":                 "text",
	"forceColors":            false,
	"disableColors":          false,
	"disableLevelTruncation": false,
	"padLevelText":           true,
	"fullTimestamp":          false,
	"disableTimestamp":       false,
	"prettyPrint":            false,
	"foo": map[string]interface{}{
		"bar": true,
		"hello": map[string]interface{}{
			"world": "world",
		},
	},
}

func configLoadDefaults() {
	for k, v := range configDefaults {
		switch v := v.(type) {
		case map[string]interface{}:
			// If v is a map, we can range over it
			for k2, v2 := range v {
				viper.SetDefault(k+"."+k2, v2)
			}
		default:
			// If v is not a map, set the default directly
			viper.SetDefault(k, v)
		}
	}
}

func configBindFlags(command cobra.Command) {
	command.Flags().VisitAll(func(flag *pflag.Flag) {
		if isRootCommand(command) {
			err := viper.BindPFlag(flag.Name, flag)
			if err != nil {
				log.Fatalf("Error initializing viper: %v", err)
			}
		} else {
			err := viper.BindPFlag(commandToConfigString(command)+"."+flag.Name, flag)
			if err != nil {
				log.Fatalf("Error initializing viper: %v", err)
			}
		}
	})
}

func writeDefaults() error {
	return writeDefaultsAs(viper.ConfigFileUsed())
}

func writeDefaultsAs(path string) error {
	newViper := viper.New()

	for k, v := range configDefaults {
		switch v := v.(type) {
		case map[string]interface{}:
			// If v is a map, we can range over it
			for k2, v2 := range v {
				newViper.SetDefault(k+"."+k2, v2)
			}
		default:
			// If v is not a map, set the default directly
			newViper.SetDefault(k, v)
		}
	}

	err := newViper.WriteConfigAs(path)
	return err
}

func getDefault(key string) any {
	return viper.Get(key)
}

func commandToConfigString(c cobra.Command) string {
	configString := c.Name()
	for parent := c.Parent(); parent != nil; parent = parent.Parent() {
		if parent.Name() != "goava" {
			configString = parent.Name() + "." + configString
		} else {
			break
		}
	}
	return configString
}

func isRootCommand(c cobra.Command) bool {
	return c.Name() == "goava"
}

func getDefaultConfigDir() string {
	var dir string
	dir, err := os.UserConfigDir()
	dir = path.Join(dir, "goava")
	if err != nil {
		log.Warnf("Could not get user config dir, using PWD. Cause: %v", err)
		dir, _ = os.Getwd()
	}
	return dir
}
