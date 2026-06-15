package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"license-guard/internal/licensecore"
)

func main() {
	databaseURL := flag.String("database-url", os.Getenv("DATABASE_URL"), "PostgreSQL connection URL")
	migrationsDir := flag.String("migrations-dir", "./migrations", "directory containing migration SQL files")
	seedDemo := flag.Bool("seed-demo", false, "also apply optional demo seed migrations")
	production := flag.Bool("production", envBool("LG_PRODUCTION", false), "refuse optional demo seed migrations in production")
	flag.Parse()

	if err := validateMigrationOptions(*production, *seedDemo); err != nil {
		log.Fatalf("invalid migration config: %v", err)
	}

	ran, err := licensecore.RunPostgresMigrations(*databaseURL, *migrationsDir, licensecore.MigrationOptions{SeedDemo: *seedDemo})
	if err != nil {
		log.Fatalf("run migrations: %v", err)
	}
	if len(ran) == 0 {
		fmt.Println("No migrations applied")
		return
	}
	for _, name := range ran {
		fmt.Printf("Applied %s\n", name)
	}
}

func validateMigrationOptions(production bool, seedDemo bool) error {
	if production && seedDemo {
		return errors.New("production mode forbids -seed-demo; seed demo data only in local or demo databases")
	}
	return nil
}

func envBool(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}
