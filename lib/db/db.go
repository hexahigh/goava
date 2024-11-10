package db

import (
	"database/sql"
	"errors"

	"github.com/bits-and-blooms/bloom/v3"
	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	// The database mode, can be "sqlite3.
	Mode string

	// In any "SQL" mode, it's the path to the database.
	Path string

	// If true, no options will be added when opening the database.
	NoOpenOptions bool

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
	return &DB{
		Mode: "sqlite3",
	}
}

func (db *DB) Init() error {
	switch db.Mode {
	case "sqlite3":
		var err error
		connPath := db.Path
		if !db.NoOpenOptions {
			connPath += "?mode=ro"
		}
		db.sqlC, err = sql.Open("sqlite3", connPath)
		if err != nil {
			return err
		}
		stats, err := db.GetHDBStats()
		if err != nil {
			return err
		}

		if db.UseBloom {

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
	default:
		return errors.New("invalid database mode")
	}

	if err := db.Ping(); err != nil {
		return err
	}

	return nil
}

func (db *DB) Close() error {
	switch db.Mode {
	case "sqlite3":
		return db.sqlC.Close()
	case "files":
		// TODO: Implement
	}
	return nil
}

func (db *DB) Ping() error {
	switch db.Mode {
	case "sqlite3":
		return db.sqlC.Ping()
	case "files":
		// TODO: Implement
	}
	return nil
}

func (db *DB) GetHDBItemFromHash(hash string) (*HDBItem, error) {
	switch db.Mode {
	case "sqlite3":
		result := db.sqlC.QueryRow("SELECT * FROM hdb WHERE hash = ?", hash)
		var item HDBItem
		err := result.Scan(&item.Hash, &item.HashType, &item.Filesize, &item.MalwareName, &item.Comment)
		return &item, err
	case "files":
		// TODO: Implement
	}
	return nil, nil
}

func (db *DB) GetHDBItemsFromHash(hash string) (*[]HDBItem, error) {
	switch db.Mode {
	case "sqlite3":
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
	case "files":
		// TODO: Implement
	}
	return nil, nil
}

func (db *DB) GetHDBItemsFromSize(size int64) (*[]HDBItem, error) {
	switch db.Mode {
	case "sqlite3":
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
	case "files":
		// TODO: Implement
	}
	return nil, nil
}

func (db *DB) GetHDBStats() (*HDBStats, error) {
	switch db.Mode {
	case "sqlite3":
		var stats HDBStats
		err := db.sqlC.QueryRow("SELECT COUNT(1) FROM hdb").Scan(&stats.Count)
		return &stats, err
	case "files":
		// TODO: Implement
	}
	return nil, nil
}

func (db *DB) HasSigWithHash(hash string) (bool, error) {
	switch db.Mode {
	case "sqlite3":
		if db.UseBloom {
			return db.bloomFilter.TestString(hash), nil
		}
		var count int
		err := db.sqlC.QueryRow("SELECT COUNT(1) FROM hdb WHERE hash = ?", hash).Scan(&count)
		return count > 0, err
	case "files":
		// TODO: Implement
	}
	return false, nil
}

func (db *DB) HasSigWithSize(size int64) (bool, error) {
	switch db.Mode {
	case "sqlite3":
		var count int
		err := db.sqlC.QueryRow("SELECT COUNT(1) FROM hdb WHERE filesize = ?", size).Scan(&count)
		return count > 0, err
	case "files":
		// TODO: Implement
	}
	return false, nil
}
