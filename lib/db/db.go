package db

import (
	"bufio"
	"database/sql"
	"os"
	"path/filepath"
	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	// Path to folder containing database files
	Path string

	// If enabled, will use a bloom filter to speed up signature lookups
	UseBloom bool

	// The false positive rate for the bloom filter.
	// Should be between 0 and 1
	BloomFalsePositiveRate float64

	// The sql database connection.
	sqlC *sql.DB

	bloomFilter *bloom.BloomFilter
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
	db.sqlC, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		return err
	}

	// Create table
	_, err = db.sqlC.Exec("CREATE TABLE hdb (hash TEXT, hash_type TEXT, filesize INTEGER, malware_name TEXT, comment TEXT)")
	if err != nil {
		return err
	}

	// Create indexes
	_, err = db.sqlC.Exec("CREATE INDEX idx_hash ON hdb (hash)")
	if err != nil {
		return err
	}
	_, err = db.sqlC.Exec("CREATE INDEX idx_filesize ON hdb (filesize)")
	if err != nil {
		return err
	}

	err = filepath.Walk(db.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// Decode Clamav hash-based signature files
		if filepath.Ext(path) == ".hdb" || filepath.Ext(path) == ".hsb" || filepath.Ext(path) == ".hdu" || filepath.Ext(path) == ".hsu" {
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
					var hashType string
					if len(values[0]) == 32 {
						hashType = "md5"
					} else if len(values[0]) == 64 {
						hashType = "sha256"
					}
					_, err = db.sqlC.Exec("INSERT INTO hdb (hash, hash_type, filesize, malware_name, comment) VALUES (?, ?, ?, ?, ?)", values[0], hashType, values[1], values[2], "")
					if err != nil {
						return err
					}
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
		stats, err := db.GetHDBStats()
		if err != nil {
			return err
		}
		// Load hashes into bloom filter
		db.bloomFilter = bloom.NewWithEstimates(uint(stats.Count), db.BloomFalsePositiveRate)
		result, err := db.sqlC.Query("SELECT hash FROM hdb")
		if err != nil {
			return err
		}
		for result.Next() {
			var hash string
			err := result.Scan(&hash)
			if err != nil {
				return err
			}
			db.bloomFilter.AddString(hash)
		}
	}

	return nil
}

func (db *DB) Close() error {

	return db.sqlC.Close()

}

func (db *DB) Ping() error {

	return db.sqlC.Ping()

}

func (db *DB) GetHDBItemFromHash(hash string) (*HDBItem, error) {

	result := db.sqlC.QueryRow("SELECT * FROM hdb WHERE hash = ?", hash)
	var item HDBItem
	err := result.Scan(&item.Hash, &item.HashType, &item.Filesize, &item.MalwareName, &item.Comment)
	return &item, err
}

func (db *DB) GetHDBItemsFromHash(hash string) (*[]HDBItem, error) {

	result, err := db.sqlC.Query("SELECT * FROM hdb WHERE hash = ?", hash)
	if err != nil {
		return nil, err
	}
	var items []HDBItem
	for result.Next() {
		var item HDBItem
		err := result.Scan(&item.Hash, &item.HashType, &item.Filesize, &item.MalwareName, &item.Comment)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return &items, err
}

func (db *DB) GetHDBItemsFromSize(size int64) (*[]HDBItem, error) {

	result, err := db.sqlC.Query("SELECT * FROM hdb WHERE filesize = ?", size)
	if err != nil {
		return nil, err
	}
	var items []HDBItem
	for result.Next() {
		var item HDBItem
		err := result.Scan(&item.Hash, &item.HashType, &item.Filesize, &item.MalwareName, &item.Comment)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return &items, err

}

func (db *DB) GetHDBStats() (*HDBStats, error) {

	var stats HDBStats
	err := db.sqlC.QueryRow("SELECT COUNT(1) FROM hdb").Scan(&stats.Count)
	return &stats, err

}

func (db *DB) HasSigWithHash(hash string) (bool, error) {

	if db.UseBloom {
		return db.bloomFilter.TestString(hash), nil
	}
	var count int
	err := db.sqlC.QueryRow("SELECT COUNT(1) FROM hdb WHERE hash = ?", hash).Scan(&count)
	return count > 0, err

}

func (db *DB) HasSigWithSize(size int64) (bool, error) {

	var count int
	err := db.sqlC.QueryRow("SELECT COUNT(1) FROM hdb WHERE filesize = ?", size).Scan(&count)
	return count > 0, err

}
