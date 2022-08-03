package cmd

import (
	"fmt"
	"os"
	"trivy-db-to/internal"
	"trivy-db-to/pkg/mysql"
	"trivy-db-to/pkg/sqlite"

	"github.com/spf13/cobra"
	"xorm.io/xorm"
)

const MYSQL = "mysql"
const SQLITE = "sqlite"

var sqltype string
var dsn string
var dropOld bool
var trivyDir string

// var outputDir string
var rootCmd = &cobra.Command{
	Use:   "trivy2sql",
	Short: "transfor trivy.db to mysql or sqlite",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var engine *xorm.Engine
		switch sqltype {
		case MYSQL:
			engine, err = internal.InitDB(dsn, mysql.Mysql{}, dropOld)
			if err != nil {
				panic("init database failed")
			}
		case SQLITE:
			engine, err = internal.InitDB(dsn, sqlite.Sqlite{}, dropOld)
			if err != nil {
				panic("init database failed")
			}
		default:
			panic(fmt.Sprintf("have not support this type %s", sqltype))
		}
		defer engine.Close()
		err = internal.Blot2Sql(trivyDir, engine)
		if err != nil {
			return err
		}
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
func init() {
	rootCmd.Flags().StringVarP(&sqltype, "sqltype", "s", "", "type of database")
	rootCmd.Flags().StringVarP(&trivyDir, "trivy-dir", "t", "db", "Dictionary of trivy.db")
	rootCmd.Flags().StringVarP(&dsn, "datasourcename", "d", "", "used to connect to database")
	rootCmd.Flags().BoolVarP(&dropOld, "cleanTable", "c", true, "whether to delete exist table in database")
}
