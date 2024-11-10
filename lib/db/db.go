package db

import (
	"database/sql"
	"errors"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	// The database mode, can be "sqlite3" or "clamav".
	Mode string

	// Behaves differently depending on the mode.
	// In any "SQL" mode, it's the path to the database.
	// In clamav mode, it's the path to a directory containing the database files.
	Path string

	// If true, no options will be added when opening the database.
	NoSqlOpenOptions bool

	// The sql database connection.
	sqlC *sql.DB
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
		if !db.NoSqlOpenOptions {
			connPath += "?mode=ro"
		}
		db.sqlC, err = sql.Open("sqlite3", connPath)
		return err
	case "clamav":
		// TODO: Implement
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
	case "clamav":
		// TODO: Implement
	}
	return nil
}

func (db *DB) Ping() error {
	switch db.Mode {
	case "sqlite3":
		return db.sqlC.Ping()
	case "clamav":
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
	case "clamav":
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
	case "clamav":
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
	case "clamav":
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
	case "clamav":
		// TODO: Implement
	}
	return nil, nil
}
