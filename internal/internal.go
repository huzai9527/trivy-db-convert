package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	db2 "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/github"
	"github.com/aquasecurity/trivy/pkg/indicator"
	"github.com/spf13/afero"
	bolt "go.etcd.io/bbolt"
	"go.etcd.io/etcd/version"
	"k8s.io/utils/clock"
	"xorm.io/xorm"

	"trivy-db-to/pkg"
	"trivy-db-to/pkg/mysql"
	"trivy-db-to/pkg/sqlite"
)

var chunkSize = 200

func FetchTrivyDB(ctx context.Context, cacheDir string, light, quiet, skipUpdate bool) error {
	_, _ = fmt.Fprintf(os.Stderr, "%s", "Fetching and updating Trivy DB ... ")
	config := db2.Config{}
	client := github.NewClient()
	progressBar := indicator.NewProgressBar(quiet)
	realClock := clock.RealClock{}
	fs := afero.NewOsFs()
	metadata := db.NewMetadata(fs, cacheDir)
	dbClient := db.NewClient(config, client, progressBar, realClock, metadata)
	needsUpdate, err := dbClient.NeedsUpdate(version.Version, light, skipUpdate)
	if err != nil {
		return err
	}
	if needsUpdate {
		_, _ = fmt.Fprint(os.Stderr, "\n")
		if err := dbClient.Download(ctx, cacheDir, light); err != nil {
			return err
		}
		if err := dbClient.UpdateMetadata(cacheDir); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", "done")
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", "done (already exist)")
	}
	return nil
}

func InitDB(dsn string, toDb interface{}, dropTable bool) (*xorm.Engine, error) {
	switch todb := toDb.(type) {
	case sqlite.Sqlite:
		err := todb.Init(dsn, dropTable)
		if err != nil {
			return &xorm.Engine{}, err
		}
		return todb.Engine, nil
	case mysql.Mysql:
		err := todb.Init(dsn, dropTable)
		if err != nil {
			return &xorm.Engine{}, err
		}
		return todb.Engine, nil
	//TODO add more db like postsql
	default:
		return &xorm.Engine{}, errors.New("don't support this db")
	}
}
func Blot2Sql(cacheDir string, engine *xorm.Engine) error {
	trivydbFile := path.Join(cacheDir, "db", "trivy.db")
	trivydb, err := bolt.Open(trivydbFile, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return err
	}
	defer trivydb.Close()
	if err := trivydb.View(func(tx *bolt.Tx) error {
		fmt.Println("start to extract vulnerability...")
		b := tx.Bucket([]byte("vulnerability"))
		c := b.Cursor()
		started := false
		ended := false
		for {
			if !started {
				k, v := c.First()
				var value pkg.Value
				json.Unmarshal(v, &value)
				vuln := pkg.Vulnerability{Cve: string(k)}
				insertValue2Vulnerablity(&vuln, value)
				engine.Insert(vuln)
				started = true
			}
			for i := 0; i < chunkSize; i++ {
				k, v := c.Next()
				if k == nil {
					ended = true
					break
				}
				var value pkg.Value
				json.Unmarshal(v, &value)
				vuln := pkg.Vulnerability{Cve: string(k)}
				insertValue2Vulnerablity(&vuln, value)
				engine.Insert(vuln)
			}
			if ended {
				break
			}
		}
		fmt.Println("vulnerability extracted successfully!")
		fmt.Println("start to extract advisory from trivydb...")
		var targetSources []string
		if err := tx.ForEach(func(source []byte, b *bolt.Bucket) error {
			s := string(source)
			if s == "trivy" || s == "vulnerability" {
				return nil
			}

			if len(targetSources) > 0 {
				found := false
				for _, ts := range targetSources {
					if strings.Contains(s, ts) {
						found = true
						break
					}
				}
				if !found {
					return nil
				}
			}

			_, _ = fmt.Fprintf(os.Stderr, ">>> %s\n", s)
			c := b.Cursor()
			for PackageName, _ := c.First(); PackageName != nil; PackageName, _ = c.Next() {
				cb := b.Bucket(PackageName)
				cbc := cb.Cursor()
				for vID, v := cbc.First(); vID != nil; vID, v = cbc.Next() {
					platform := []byte(s)
					segment := []byte("")
					splited := strings.Split(s, " ")
					if len(splited) > 1 {
						platform = []byte(strings.Join(splited[0:len(splited)-1], " "))
						segment = []byte(splited[len(splited)-1])
					}
					VulnerabilityAdvisoryIns := pkg.VulnerabilityAdvisory{
						Cve:         string(vID),
						Platform:    string(platform),
						Segment:     string(segment),
						PackageName: string(PackageName),
					}
					adv := pkg.Advisory{}
					json.Unmarshal(v, &adv)
					insertValue2VulnerabilityAdvisory(&VulnerabilityAdvisoryIns, adv)
					engine.Insert(VulnerabilityAdvisoryIns)
				}
			}
			return nil
		}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// func Sql2Blot(blotDir string, engine *xorm.Engine) error {
// 	fmt.Println("start to convert sql to bbolt...")
// 	defer fmt.Println("convert successfully!")
// 	var bt bboltdb.Bbolt
// 	boltDb, err := bt.Init(blotDir)
// 	if err != nil {
// 		return err
// 	}
// 	// convert vulnerability
// 	var maxId int64
// 	has, err := engine.SQL("select max(id) from vulnerability").Get(&maxId)
// 	if err != nil {
// 		return err
// 	}
// 	if has {
// 		for id := 1; id <= int(maxId); id++ {
// 			vuln := new(pkg.Vulnerability)
// 			engine.ID(id).Get(vuln)
// 			boltDb.Update(func(tx *bolt.Tx) error {
// 				tx.CreateBucketIfNotExists([]byte("vulnerability"))
// 				bkt := tx.Bucket([]byte("vulnerability"))
// 				bkt.Put([]byte(vuln.Cve), []byte(vuln.Value))
// 				return nil
// 			})
// 		}
// 	}

// 	has, err = engine.SQL("select max(id) from vulnerability_advisory").Get(&maxId)
// 	if err != nil {
// 		return err
// 	}
// 	if has {
// 		for id := 1; id <= int(maxId); id++ {
// 			adv := new(pkg.VulnerabilityAdvisory)
// 			engine.ID(id).Get(adv)
// 			boltDb.Update(func(tx *bolt.Tx) error {
// 				platform := adv.Platform + " " + adv.Segment
// 				tx.CreateBucketIfNotExists([]byte(platform))
// 				bkt := tx.Bucket([]byte(platform))
// 				pkgbkt, err := bkt.CreateBucketIfNotExists([]byte(adv.PackageName))
// 				if err != nil {
// 					return err
// 				}
// 				pkgbkt.Put([]byte(adv.Cve), []byte(adv.Value))
// 				return nil
// 			})
// 		}
// 	}

// 	return nil
// }
func insertValue2Vulnerablity(Vuln *pkg.Vulnerability, v pkg.Value) {
	Vuln.Title = v.Title
	Vuln.Description = v.Description
	Vuln.CVSS = v.CVSS
	Vuln.Severity = v.Severity
	Vuln.VendorSeverity = v.VendorSeverity
	Vuln.CweIDs = v.CweIDs
	Vuln.References = v.References
	Vuln.LastModifiedDate = v.LastModifiedDate
	Vuln.PublishedDate = v.PublishedDate
}

func insertValue2VulnerabilityAdvisory(adv *pkg.VulnerabilityAdvisory, v pkg.Advisory) {
	adv.AffectedVersion = v.AffectedVersion
	adv.Arches = v.Arches
	adv.DataSource = v.DataSource
	adv.FixedVersion = v.FixedVersion
	adv.PatchedVersions = v.PatchedVersions
	adv.State = v.State
	adv.Severity = v.Severity
	adv.UnaffectedVersions = v.UnaffectedVersions
	adv.VendorIDs = v.VendorIDs
	adv.VulnerabilityID = v.VulnerabilityID
	adv.VulnerableVersions = v.VulnerableVersions
}
