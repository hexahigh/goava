package db

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	_ "github.com/mattn/go-sqlite3"
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
	Logger log.Logger

	// What should be done if a signature has an unknown size
	//
	// 0: Ignore the signature
	// 1: Make the size check always return true, effectively disabling it
	UnknownSizeAction int

	sizeAlwaysTrue bool

	// The sql database connection.
	sqlC *sql.DB

	bloomFilter *bloom.BloomFilter

	Hashes *[]string
	Sizes  *[]int

	hashes     []string
	sizes      []int
	hashToItem map[string]*HDBItem
}

type HDBItem struct {
	Hash        string
	HashType    string
	Filesize    int
	MalwareName string
	Comment     string
}

type HDBStats struct {
	Count int
}

// It's recommended to instantiate your own DB instance
func New() *DB {
	return &DB{}
}

// Init initializes the DB by setting up the hashToItem map.
func (db *DB) Init() error {
	// Initialize hashToItem as an empty map
	db.hashToItem = make(map[string]*HDBItem)

	db.Hashes = &db.hashes
	db.Sizes = &db.sizes

	return nil
}

// LoadAll calls LoadSigs and LoadBloom.
// Should be called after Init
func (db *DB) LoadAll() error {
	if err := db.LoadSigs(); err != nil {
		return err
	}
	db.LoadBloom()
	return nil
}

// LoadSigs loads Clamav hash-based signature files, as well as Goava CSV files.
//
// The function will walk the directory specified in Path and load all files
// with the following extensions: .hdb, .hsb, .hdu, .hsu, and .csv.
//
// For .hdb, .hsb, .hdu, .hsu files, the function will parse the file and
// extract the hashes, sizes, and malware names. Hashes that have unknown
// sizes will be skipped or disable size checks depending on the value of
// UnknownSizeAction.
//
// For .csv files, the function will parse the file and extract the hashes,
// sizes, malware names, and comments.
//
// The loaded signatures will be stored in the hashToItem map, with the hash
// as the key and the HDBItem as the value.
//
// The function will also sort the hashes and sizes for use with the
// HasSigWithHash and HasSigWithSize methods.
//
// The function will return an error if there is a problem loading the
// signatures.
//
// Should be called after Init
func (db *DB) LoadSigs() error {
	db.nl(func() { db.Logger.Print("Loading signatures...") })
	err := filepath.Walk(db.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		switch filepath.Ext(path) {
		// Decode Clamav hash-based signature files
		case ".hdb", ".hsb", ".hdu", ".hsu":
			db.nl(func() { db.Logger.Printf("Loading %s", path) })
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
					var fileSize int64
					if values[1] == "*" {
						if db.UnknownSizeAction == 1 {
							db.nl(func() {
								db.Logger.Printf("%s contains a signature with unknown size, disabling size checks", path)
							})
							db.sizeAlwaysTrue = true
						} else if db.UnknownSizeAction == 0 {
							db.nl(func() {
								db.Logger.Printf("%s contains a signature with unknown size, skipping signature", path)
							})
							continue
						}
						fileSize = -1
					} else {
						fileSize, err = strconv.ParseInt(values[1], 10, 64)
						if err != nil {
							return err
						}
					}

					var hashType string
					switch len(values[0]) {
					case 32:
						hashType = "md5"
					case 40:
						hashType = "sha1"
					case 64:
						hashType = "sha256"
					}
					db.hashes = append(db.hashes, values[0])
					db.sizes = append(db.sizes, int(fileSize))

					db.hashToItem[values[0]] = &HDBItem{
						Hash:        values[0],
						HashType:    hashType,
						Filesize:    int(fileSize),
						MalwareName: values[2],
					}
				}
			}
			if err := scanner.Err(); err != nil {
				return err
			}
		case ".csv":
			db.nl(func() { db.Logger.Printf("Loading %s", path) })
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
					fileSize, err := strconv.ParseInt(values[2], 10, 64)
					if err != nil {
						return err
					}
					db.hashes = append(db.hashes, values[0])
					db.sizes = append(db.sizes, int(fileSize))
					db.hashToItem[values[0]] = &HDBItem{
						Hash:        values[0],
						HashType:    values[1],
						Filesize:    int(fileSize),
						MalwareName: values[3],
						Comment:     values[4],
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

	// Sort hashes and sizes
	db.nl(func() { db.Logger.Print("Sorting hashes and sizes...") })
	slices.Sort(db.sizes)
	slices.Sort(db.hashes)

	return nil
}

// LoadBloom initializes the bloom filter if the UseBloom flag is set to true.
// Should be called after Init and LoadSigs
func (db *DB) LoadBloom() {
	if db.UseBloom {
		db.nl(func() { db.Logger.Print("Creating bloom filter...") })
		// Load hashes into bloom filter
		db.bloomFilter = bloom.NewWithEstimates(uint(len(db.hashes)), db.BloomFalsePositiveRate)
		for _, hash := range db.hashes {
			db.bloomFilter.AddString(hash)
		}
	}
}

// Close releases any resources used by the database, such as closing the
// underlying connection.
//
// Deprecated: No longer used
func (db *DB) Close() error {
	return nil
}

// Ping returns an error if the database is not accessible, otherwise it returns nil.
//
// Deprecated: No longer used
func (db *DB) Ping() error {
	return nil
}

// HasSigWithHash returns true if a signature with the given hash exists in the database.
// The search is done using a binary search.
// If the bloom filter is enabled, it will be used to speed up the search further.
func (db *DB) HasSigWithHash(hash string) (bool, error) {

	if db.UseBloom {
		return db.bloomFilter.TestString(hash), nil
	}
	// Check if hash exists using binary search
	index := sort.SearchStrings(db.hashes, hash)
	return index < len(db.hashes) && db.hashes[index] == hash, nil

}

// HasSigWithSize returns true if a signature with the given size exists in the database.
// Uses a binary search.
// Will always return true if sizeAlwaysTrue is true, this value is set if a signature has an unknown size
func (db *DB) HasSigWithSize(size int) (bool, error) {

	if db.sizeAlwaysTrue {
		return true, nil
	}

	index := sort.SearchInts(db.sizes, size)
	return index < len(db.sizes) && db.sizes[index] == size, nil
}

// GetItemByHash returns the HDBItem associated with the given hash, or an error
// if the hash is not found.
func (db *DB) GetItemByHash(hash string) (*HDBItem, error) {
	index := sort.SearchStrings(db.hashes, hash)
	if index >= len(db.hashes) || db.hashes[index] != hash {
		return nil, fmt.Errorf("hash %s not found", hash)
	}
	return db.hashToItem[hash], nil
}

// GetItemBySize returns the HDBItem associated with the given size, or an error
// if no item is found. The search is done using a brute force linear search,
// and is therefore MUCH slower than GetItemByHash.
func (db *DB) GetItemBySize(size int) (*HDBItem, error) {
	// Brute force search
	for _, item := range db.hashToItem {
		if item.Filesize == size {
			return item, nil
		}
	}
	return nil, fmt.Errorf("item with size %d not found", size)
}

func (db *DB) GetHDBStats() HDBStats {
	return HDBStats{
		Count: len(db.hashes),
	}
}

// Runs the specified function if Log is true
func (db *DB) nl(f func()) {
	if db.Log {
		f()
	}
}
