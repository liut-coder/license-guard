package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"license-guard/internal/licensecore"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8090", "HTTP listen address")
	dataDir := flag.String("data-dir", "./data", "directory for local JSON data and signing keys")
	keyDir := flag.String("key-dir", "", "directory for signing keys; defaults to data-dir")
	adminDir := flag.String("admin-dir", "./web/admin", "directory for static admin UI")
	storeMode := flag.String("store", envOrDefault("LG_STORE", "json"), "storage backend: json or postgres")
	databaseURL := flag.String("database-url", os.Getenv("DATABASE_URL"), "PostgreSQL connection URL when -store=postgres")
	autoMigrate := flag.Bool("auto-migrate", false, "apply PostgreSQL schema migrations before starting")
	migrationsDir := flag.String("migrations-dir", "./migrations", "directory containing PostgreSQL migration SQL files")
	corsAllowedOrigins := flag.String("cors-allowed-origins", envOrDefault("LG_CORS_ALLOWED_ORIGINS", "*"), "comma-separated CORS allowed origins; use concrete HTTPS origins in production")
	flag.Parse()

	resolvedKeyDir := *keyDir
	if resolvedKeyDir == "" {
		resolvedKeyDir = *dataDir
	}

	store, err := buildStore(*storeMode, *dataDir, *databaseURL, *autoMigrate, *migrationsDir)
	if err != nil {
		log.Fatalf("init store: %v", err)
	}
	api, err := licensecore.NewServerWithStore(resolvedKeyDir, store)
	if err != nil {
		log.Fatalf("init license guard server: %v", err)
	}
	api.SetCORSAllowedOrigins(strings.Split(*corsAllowedOrigins, ","))

	mux := http.NewServeMux()
	mux.HandleFunc("/admin-ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin-ui/", http.StatusTemporaryRedirect)
	})
	mux.Handle("/admin-ui/", http.StripPrefix("/admin-ui/", http.FileServer(http.Dir(*adminDir))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/admin-ui/", http.StatusTemporaryRedirect)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/admin-ui/") {
			http.NotFound(w, r)
			return
		}
		api.ServeHTTP(w, r)
	})

	log.Printf("License Guard API listening on http://%s", *addr)
	log.Printf("License Guard Admin UI: http://%s/admin-ui/", *addr)
	log.Printf("Storage backend: %s", store.Name())
	log.Printf("Demo admin: %s / %s", licensecore.DemoAdminAccount, licensecore.DemoAdminPass)
	log.Printf("Demo app: %s", licensecore.DemoAppID)
	log.Printf("Demo license: %s", licensecore.DemoLicenseKey)
	log.Printf("Demo integrity hash: %s", licensecore.DemoBinaryHash)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func buildStore(mode string, dataDir string, databaseURL string, autoMigrate bool, migrationsDir string) (licensecore.Store, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "json":
		return licensecore.NewJSONStore(dataDir)
	case "postgres", "postgresql":
		if autoMigrate {
			ran, err := licensecore.RunPostgresMigrations(databaseURL, migrationsDir, licensecore.MigrationOptions{})
			if err != nil {
				return nil, err
			}
			log.Printf("Applied PostgreSQL migrations: %s", strings.Join(ran, ", "))
		}
		return licensecore.NewPostgresStore(databaseURL)
	default:
		return nil, fmt.Errorf("unsupported store backend %q", mode)
	}
}

func envOrDefault(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
