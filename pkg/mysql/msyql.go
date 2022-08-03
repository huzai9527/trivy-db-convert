package mysql

import (
	"trivy-db-to/pkg"

	_ "github.com/go-sql-driver/mysql"
	"xorm.io/xorm"
)

type Mysql struct {
	Engine *xorm.Engine
}

func (m *Mysql) Init(dns string, dropTable bool) error {
	engine, err := xorm.NewEngine("mysql", dns)
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
	m.Engine = engine
	return nil
}
