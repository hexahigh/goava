package cmd

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/dustin/go-humanize"
	"github.com/hexahigh/goava/lib/db"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	scanCmd.Flags().StringP("database", "d", "", "Path to database")
	scanCmd.Flags().BoolP("recursive", "r", false, "Scan recursively")
	scanCmd.Flags().Bool("skip-size", false, "Skip size check, can increase speed at the cost of having to read every file")
	scanCmd.Flags().Bool("no-summary", false, "Don't print summary")
	scanCmd.Flags().Bool("full-path", false, "Print full path of scanned files")
	scanCmd.Flags().BoolP("use-bloom", "b", true, "Use a bloom filter to speed up scanning")
	scanCmd.Flags().Float64("bloom-fpr", 0.01, "False positive rate for bloom filter. Lower values increase accuracy and ram usage")

	rootCmd.AddCommand(scanCmd)

	configBindFlags(*scanCmd)
}

var scanCmd = &cobra.Command{
	Use:   "scan path...",
	Short: "Scan for viruses",
	Long:  `Scan for viruses`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		c := commandToConfigString(*cmd)

		var stats struct {
			ScannedFiles   int
			ScannedFolders int
			InfectedFiles  int
			DataScanned    uint64
			DataRead       uint64
		}

		var database = &db.DB{
			Mode:                   "sqlite3",
			Path:                   viper.GetString(c + ".database"),
			UseBloom:               viper.GetBool(c + ".use-bloom"),
			BloomFalsePositiveRate: viper.GetFloat64(c + ".bloom-fpr"),
		}

		if err := database.Init(); err != nil {
			fmt.Println(err)
			log.Panic(err)
		}
		defer database.Close()

		//* Functions

		scanFile := func(path string) {
			if viper.GetBool(c + ".full-path") {
				path, _ = filepath.Abs(path)
			}
			file, err := os.OpenFile(path, os.O_RDONLY, 0644)
			if err != nil {
				log.Errorf("Error opening file: %v", err)
				return
			}
			defer file.Close()

			stat, err := file.Stat()
			if err != nil {
				log.Errorf("Error getting file stat: %v", err)
				return
			}
			filesize := stat.Size()

			stats.ScannedFiles++
			stats.DataScanned += uint64(filesize)

			if !viper.GetBool(c + ".skip-size") {
				// Check if size matches
				hdbItems, err := database.GetHDBItemsFromSize(filesize)
				if err != nil {
					log.Errorf("Error getting hdb items: %v", err)
					return
				}

				if len(*hdbItems) == 0 {
					log.Infof("No viruses found in %s", path)
					return
				}
			}

			// Hash file
			md5 := md5.New()
			written, err := io.Copy(md5, file)
			if err != nil {
				log.Errorf("Error hashing file: %v", err)
				return
			}

			stats.DataRead += uint64(written)

			hash := hex.EncodeToString(md5.Sum(nil))

			hashExists, err := database.HasSigWithHash(hash)
			if err != nil {
				log.Errorf("Error checking if hash exists: %v", err)
				return
			}

			if !hashExists {
				log.Infof("No viruses found in %s", path)
				return
			} else {
				stats.InfectedFiles++
				log.Warnf("Virus found in %s", path)
			}

		}

		scanDir := func(path string) error {
			stats.ScannedFolders++
			return filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					scanFile(path)
				}
				return nil
			})
		}

		//* End functions

		for _, path := range args {
			// Check if path is a directory
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				if viper.GetBool(c + ".recursive") {
					err := scanDir(path)
					if err != nil {
						log.Errorf("Error walking path: %v", err)
					}
				} else {
					log.Infof("%s is a directory, ignoring", path)
				}
			} else {
				scanFile(path)
			}
		}

		if !viper.GetBool(c + ".no-summary") {
			hdbStats, err := database.GetHDBStats()
			if err != nil {
				log.Errorf("Error getting hdb stats: %v", err)
				return
			}
			log.Info("----------- SCAN SUMMARY -----------")
			log.Info("Scanned files: ", stats.ScannedFiles)
			log.Info("Scanned folders: ", stats.ScannedFolders)
			log.Info("Infected files: ", stats.InfectedFiles)
			log.Info("Data scanned: ", humanize.Bytes(stats.DataScanned))
			log.Info("Data read: ", humanize.Bytes(stats.DataRead))
			log.Infof("Known viruses: %d", hdbStats.Count)
		}
	},
}
