package bboltdb

import (
	"path"
	"time"

	bolt "go.etcd.io/bbolt"
)

type Bbolt struct {
}

func (b *Bbolt) Init(boltDir string) (*bolt.DB, error) {
	boltFile := path.Join(boltDir, "db", "bolt.db")
	boltDb, err := bolt.Open(boltFile, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return &bolt.DB{}, err
	}
	return boltDb, nil
}
