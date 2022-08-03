package sqlite

import (
	"trivy-db-to/pkg"

	_ "github.com/mattn/go-sqlite3"
	"xorm.io/xorm"
)

type Sqlite struct {
	Engine *xorm.Engine
}

func (s *Sqlite) Init(dbPath string, dropTable bool) error {
	engine, err := xorm.NewEngine("sqlite3", dbPath)
	if err != nil {
		return err
	}
	if dropTable {
		pkg.DropTables(engine)
	}
	engine.Sync2(new(pkg.Vulnerability), new(pkg.VulnerabilityAdvisory))
	if err != nil {
		return err
	}
	s.Engine = engine
	return nil
}
