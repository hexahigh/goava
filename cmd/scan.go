package cmd

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/hexahigh/goava/lib/db"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	scanCmd.Flags().StringP("database", "d", "", "Path to folder containing database files")
	scanCmd.Flags().BoolP("recursive", "r", false, "Scan recursively")
	scanCmd.Flags().Bool("skip-size", false, "Skip size check, can increase speed at the cost of having to read every file")
	scanCmd.Flags().Bool("no-summary", false, "Don't print summary")
	scanCmd.Flags().Bool("full-path", false, "Print full path of scanned files")
	scanCmd.Flags().BoolP("use-bloom", "b", true, "Use a bloom filter to speed up scanning")
	scanCmd.Flags().Float64("bloom-fpr", 0.001, "False positive rate for bloom filter. Lower values increase accuracy and ram usage")
	scanCmd.Flags().BoolP("indexes", "i", false, "Create indexes on database")
	scanCmd.Flags().BoolP("infected", "I", false, "Only print infected files, will still print summary")
	scanCmd.Flags().BoolP("symlinks", "s", false, "Resolve symbolic links")
	scanCmd.Flags().BoolP("db-log", "L", true, "Enable logs from the database handler")

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

		startTime := time.Now()

		var stats struct {
			ScannedFiles   int
			ScannedFolders int
			InfectedFiles  int
			DataScanned    uint64
			DataRead       uint64
		}

		var database = &db.DB{
			Path:                   viper.GetString(c + ".database"),
			UseBloom:               viper.GetBool(c + ".use-bloom"),
			BloomFalsePositiveRate: viper.GetFloat64(c + ".bloom-fpr"),
			CreateIndexes:          viper.GetBool(c + ".indexes"),
			Log:                    viper.GetBool(c + ".db-log"),
			Logger:                 log.StandardLogger(),
		}

		//* Functions

		scanFile := func(path string) {
			var err error
			if viper.GetBool(c + ".full-path") {
				path, _ = filepath.Abs(path)
			}
			//* Resolve symlinks if enabled
			if viper.GetBool(c + ".symlinks") {
				path, err = filepath.EvalSymlinks(path)
				if err != nil {
					log.Errorf("Error resolving symlink: %v", err)
					return
				}
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

			if stat.IsDir() {
				log.Errorf("%s is a directory, this shouldn't happen, skipping", path)
				return
			}

			stats.ScannedFiles++
			stats.DataScanned += uint64(filesize)

			//* Symlink was not resolved so we skip it
			if stat.Mode()&os.ModeSymlink != 0 {
				log.Infof("%s is a symlink, skipping", path)
				return
			}

			if stat.Mode()&os.ModeDevice != 0 {
				log.Infof("%s is a device, skipping", path)
				return
			}

			if stat.Mode()&os.ModeNamedPipe != 0 {
				log.Infof("%s is a pipe, skipping", path)
				return
			}

			if stat.Mode()&os.ModeSocket != 0 {
				log.Infof("%s is a socket, skipping", path)
				return
			}

			if filesize == 0 {
				if !viper.GetBool(c + ".infected") {
					log.Infof("No viruses found in %s", path)
				}
				return
			}

			if !viper.GetBool(c + ".skip-size") {
				// Check if size matches
				sizeExists, err := database.HasSigWithSize(int(filesize))
				if err != nil {
					log.Errorf("Error checking if size exists: %v", err)
					return
				}
				if !sizeExists {
					if !viper.GetBool(c + ".infected") {
						log.Infof("No viruses found in %s", path)
					}
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
				if !viper.GetBool(c + ".infected") {
					log.Infof("No viruses found in %s", path)
				}
				return
			} else {
				stats.InfectedFiles++
				log.Warnf("Virus found in %s", path)
			}
		}

		scanDir := func(path string) error {
			return filepath.Walk(path, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}

				// Check if the path is a symlink
				if info.Mode()&os.ModeSymlink != 0 {
					if !viper.GetBool(c + ".symlinks") {
						if !viper.GetBool(c + ".infected") {
							log.Infof("%s is a symlink, skipping", path)
						}
						return nil
					}
					// If it's a symlink, resolve it
					realPath, err := filepath.EvalSymlinks(path)
					if err != nil {
						log.Warnf("Failed to resolve symlink %s: %v", path, err)
						return nil
					}

					// Get the actual file info of the resolved path
					stat, err := os.Stat(realPath)
					if err != nil {
						log.Warnf("Failed to stat resolved path %s: %v", realPath, err)
						return nil
					}

					// Update the info variable with the resolved path's information
					info = stat
				}

				if !info.IsDir() {
					scanFile(path)
				} else {
					stats.ScannedFolders++
				}

				return nil
			})
		}

		//* End functions

		if err := database.Init(); err != nil {
			log.Panic(err)
		}
		if err := database.LoadAll(); err != nil {
			log.Panic(err)
		}

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

		endTime := time.Now()

		HDBStats := database.GetHDBStats()

		if !viper.GetBool(c + ".no-summary") {
			log.Info("----------- SCAN SUMMARY -----------")
			log.Info("Known viruses: ", HDBStats.Count)
			log.Info("Scanned files: ", stats.ScannedFiles)
			log.Info("Scanned folders: ", stats.ScannedFolders)
			log.Info("Infected files: ", stats.InfectedFiles)
			log.Info("Data scanned: ", humanize.Bytes(stats.DataScanned))
			log.Info("Data read: ", humanize.Bytes(stats.DataRead))
			log.Info("Time: ", endTime.Sub(startTime).String())
		}
	},
}
