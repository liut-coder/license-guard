package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"license-guard/internal/licensecore"
)

func main() {
	databaseURL := flag.String("database-url", os.Getenv("DATABASE_URL"), "PostgreSQL connection URL")
	migrationsDir := flag.String("migrations-dir", "./migrations", "directory containing migration SQL files")
	seedDemo := flag.Bool("seed-demo", false, "also apply optional demo seed migrations")
	flag.Parse()

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
