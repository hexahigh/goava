package cmd

import (
	"os"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "goava",
	Short: "Virus scanner written in go!",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	initConfig()
}

func initConfig() {
	configLoadDefaults()
	//* Load flags
	rootCmd.PersistentFlags().Int8P("verbosity", "v", 4, "verbosity level. 0=panic, 1=fatal, 2=error, 3=warn, 4=info, 5=debug, 6=trace")
	rootCmd.PersistentFlags().StringP("config-dir", "D", getDefaultConfigDir(), "Directory containing data and config files")
	rootCmd.PersistentFlags().StringP("config-file", "C", "config.toml", "Name of the config file, with extension")
	rootCmd.PersistentFlags().String("output", "text", "Output mode. Supported values are: text, json")
	rootCmd.PersistentFlags().Bool("forceColors", false, "Force colors in log output. Only works if output mode is Text")
	rootCmd.PersistentFlags().Bool("disableColors", false, "Disable colors in log output. Only works if output mode is Text")
	rootCmd.PersistentFlags().Bool("disableLevelTruncation", false, "When colors are enabled, levels are truncated to 4 characters by default, this disables that. Only works if output mode is Text")
	rootCmd.PersistentFlags().Bool("padLevelText", true, "Pads level text for better readability. Only works if output mode is Text")
	rootCmd.PersistentFlags().Bool("fullTimestamp", false, "Show full timestamp in log output. Only works if output mode is Text")
	rootCmd.PersistentFlags().Bool("disableTimestamp", false, "Disable timestamp in log output. Works for both text and json output")
	rootCmd.PersistentFlags().Bool("prettyPrint", false, "Indent json output. Not sure why you would want this, but here you go.")
	rootCmd.ParseFlags(os.Args[1:])

	configBindFlags(*rootCmd)

	//* Load env vars
	viper.SetEnvPrefix("GOAVA")
	viper.AutomaticEnv()

	//* Set config file options
	viper.SetConfigName(viper.GetString("config-file"))
	viper.SetConfigType("toml")
	viper.AddConfigPath(viper.GetString("config-dir"))

	//* Load config file
	err := os.MkdirAll(viper.GetString("config-dir"), 0700)
	if err != nil {
		log.Warnf("Could not create config dir. Cause: %v", err)
	}
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Warnf("Could not find config file, making one. Cause: %v", err)
			err = writeDefaultsAs(path.Join(viper.GetString("config-dir"), viper.GetString("config-file")))
			if err != nil {
				log.Warnf("Could not write config file. Cause: %v", err)
			}
		} else {
			log.Errorf("Could not read config file. Cause: %v", err)
		}
	}

	log.SetLevel(log.Level(viper.GetInt("verbosity")))
	switch strings.ToLower(viper.GetString("output")) {
	case "text":
		log.SetFormatter(&log.TextFormatter{
			ForceColors:            viper.GetBool("forceColors"),
			DisableColors:          viper.GetBool("disableColors"),
			DisableLevelTruncation: viper.GetBool("disableLevelTruncation"),
			PadLevelText:           viper.GetBool("padLevelText"),
			FullTimestamp:          viper.GetBool("fullTimestamp"),
			DisableTimestamp:       viper.GetBool("disableTimestamp"),
		})
	case "json":
		log.SetFormatter(&log.JSONFormatter{
			DisableTimestamp: viper.GetBool("disableTimestamp"),
			PrettyPrint:      viper.GetBool("prettyPrint"),
		})
	default:
		log.Fatalf("Unknown output mode: %s", viper.GetString("output"))
	}

	for key, value := range viper.GetViper().AllSettings() {
		log.WithFields(log.Fields{
			key: value,
		}).Debug("Command Flag")
	}
}
