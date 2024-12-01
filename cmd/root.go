package cmd

import (
	"os"
	"path"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// The root zerolog logger
var logger zerolog.Logger

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
	rootCmd.PersistentFlags().Int8P("verbosity", "v", 1, "verbosity level. -1 = trace, 0 = debug, 1 = info, 2 = warn, 3 = error, 4 = fatal, 5 = panic")
	rootCmd.PersistentFlags().StringP("config-dir", "D", getDefaultConfigDir(), "Directory containing data and config files")
	rootCmd.PersistentFlags().StringP("config-file", "C", "config.toml", "Name of the config file, with extension")
	rootCmd.PersistentFlags().Bool("config-reset", false, "Reset config file to defaults")
	rootCmd.PersistentFlags().String("output", "text", "Output mode. Supported values are: text, json")
	rootCmd.PersistentFlags().Bool("disableColors", false, "Disable colors in log output. Only works if output mode is Text")
	rootCmd.PersistentFlags().Bool("fullTimestamp", false, "Show full timestamp in log output. Only works if output mode is Text")
	rootCmd.PersistentFlags().Bool("disableTimestamp", false, "Disable timestamp in log output. Works for both text and json output")
	rootCmd.PersistentFlags().Bool("prettyPrint", false, "Indent json output. Not sure why you would want this, but here you go.")
	rootCmd.PersistentFlags().Bool("caller", false, "Show caller in log output.")
	rootCmd.ParseFlags(os.Args[1:])

	configBindFlags(*rootCmd)

	//* Load env vars
	viper.SetEnvPrefix("GOAVA")
	viper.AutomaticEnv()

	//* Set config file options
	viper.SetConfigName(viper.GetString("config-file"))
	viper.SetConfigType("toml")
	viper.AddConfigPath(viper.GetString("config-dir"))

	//? These log statements do nothing since the logger is not initialized yet. Not sure where they should write. It shouldn't really matter however as all errors are ignored.
	//* Load config file
	err := os.MkdirAll(viper.GetString("config-dir"), 0700)
	if err != nil {
		logger.Warn().Msgf("Could not create config dir. Cause: %v", err)
	}
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			err = writeDefaultsAs(path.Join(viper.GetString("config-dir"), viper.GetString("config-file")))
			if err != nil {
				logger.Warn().Msgf("Could not write config file. Cause: %v", err)
			}
		} else {
			logger.Warn().Msgf("Could not read config file. Cause: %v", err)
		}
	}

	//* Check if config should be reset
	if viper.GetBool("config-reset") {
		err = writeDefaults()
		if err != nil {
			logger.Warn().Msgf("Could not write config file. Cause: %v", err)
		}
	}

	switch viper.GetString("output") {
	case "text":
		timeformat := "15:04"
		if viper.GetBool("fullTimestamp") {
			timeformat = time.RFC3339
		}
		output := zerolog.ConsoleWriter{Out: os.Stdout, NoColor: viper.GetBool("disableColors"), TimeFormat: timeformat}
		if viper.GetBool("disableTimestamp") {
			output.PartsOrder = []string{
				zerolog.LevelFieldName,
				zerolog.MessageFieldName,
			}
		}
		logger = zerolog.New(output)
	case "json":
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
		logger = zerolog.New(os.Stdout)
	default:
		logger.Fatal().Msgf("Unsupported output mode: %s", viper.GetString("output"))
	}

	if !viper.GetBool("disableTimestamp") {
		logger = logger.With().Timestamp().Logger()
	}
	if viper.GetBool("caller") {
		logger = logger.With().Caller().Logger()
	}
	logger = logger.Level(zerolog.Level(viper.GetInt("verbosity")))

	for key, value := range viper.GetViper().AllSettings() {
		logger.Debug().Msgf("%s: %v", key, value)
	}
}
