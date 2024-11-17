package db

import (
	"bufio"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

type DB struct {
	// Path to folder containing database files
	Path string

	// If enabled, will use a bloom filter to speed up signature lookups
	UseBloom bool

	CreateIndexes bool

	// The false positive rate for the bloom filter.
	// Should be between 0 and 1
	BloomFalsePositiveRate float64

	// If enabled, will print log messages
	Log bool

	// The logger
	Logger *logrus.Logger

	// The sql database connection.
	sqlC *sql.DB

	bloomFilter *bloom.BloomFilter

	hashes []string
	sizes  []int
}

type HDBItem struct {
	Hash        string
	HashType    string
	Filesize    int64
	MalwareName string
	Comment     string
}

type HDBStats struct {
	Count int64
}

// It's recommended to instantiate your own DB instance
func New() *DB {
	return &DB{}
}

func (db *DB) Init() error {
	var err error

	db.nl(func() { db.Logger.Info("Loading signatures...") })
	err = filepath.Walk(db.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// Decode Clamav hash-based signature files
		if filepath.Ext(path) == ".hdb" || filepath.Ext(path) == ".hsb" || filepath.Ext(path) == ".hdu" || filepath.Ext(path) == ".hsu" {
			db.nl(func() { db.Logger.Infof("Loading %s", path) })
			osfile, err := os.OpenFile(path, os.O_RDONLY, 0)
			if err != nil {
				return err
			}
			defer osfile.Close()
			scanner := bufio.NewScanner(osfile)
			for scanner.Scan() {
				line := scanner.Text()
				if len(line) > 0 {
					values := strings.Split(line, ":")
					db.hashes = append(db.hashes, values[0])
					fileSize, err := strconv.ParseInt(values[2], 10, 64)
					if err != nil {
						return err
					}
					db.sizes = append(db.sizes, int(fileSize))
				}
			}
			if err := scanner.Err(); err != nil {
				return err
			}
		}

		if filepath.Ext(path) == ".csv" {
			db.nl(func() { db.Logger.Infof("Loading %s", path) })
			osfile, err := os.OpenFile(path, os.O_RDONLY, 0)
			if err != nil {
				return err
			}
			defer osfile.Close()
			scanner := bufio.NewScanner(osfile)
			for scanner.Scan() {
				line := scanner.Text()
				if len(line) > 0 {
					values := strings.Split(line, ",")
					db.hashes = append(db.hashes, values[0])
					fileSize, err := strconv.ParseInt(values[2], 10, 64)
					if err != nil {
						return err
					}
					db.sizes = append(db.sizes, int(fileSize))
				}
			}
			if err := scanner.Err(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	if db.UseBloom {
		db.nl(func() { db.Logger.Info("Creating bloom filter...") })
		// Load hashes into bloom filter
		db.bloomFilter = bloom.NewWithEstimates(uint(len(db.hashes)), db.BloomFalsePositiveRate)
		for _, hash := range db.hashes {
			db.bloomFilter.AddString(hash)
		}
	}

	// Sort hashes and sizes
	db.nl(func() { db.Logger.Info("Sorting hashes and sizes...") })
	sort.Ints(db.sizes)
	sort.Strings(db.hashes)

	return nil
}

func (db *DB) Close() error {

	return nil

}

func (db *DB) Ping() error {

	return nil

}

func (db *DB) HasSigWithHash(hash string) (bool, error) {

	if db.UseBloom {
		return db.bloomFilter.TestString(hash), nil
	}
	// Check if hash exists using binary search
	index := sort.SearchStrings(db.hashes, hash)
	return index < len(db.hashes) && db.hashes[index] == hash, nil

}

func (db *DB) HasSigWithSize(size int) (bool, error) {

	index := sort.SearchInts(db.sizes, size)
	return index < len(db.sizes) && db.sizes[index] == size, nil
}

// Runs the specified function if Log is true
func (db *DB) nl(f func()) {
	if db.Log {
		f()
	}
}
