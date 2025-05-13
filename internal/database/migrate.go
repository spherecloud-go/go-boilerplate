package database

import (
	"fmt"
	"log"

	"github.com/spherecloud-go/go-boilerplate/internal/config"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres" // DB driver for migrate
	_ "github.com/golang-migrate/migrate/v4/source/file"       // 'file://' source driver for migrate
)

// RunMigrations executes database migrations from the 'migrations' folder.
// This function is optional if you prefer to run migrations exclusively via the Makefile and 'migrate' CLI.
func RunMigrations(cfg *config.Config) error {
	migrationsPath := "file://migrations" // Relative to project root

	// Construct DSN from config for migrate tool
	// Note: migrate CLI uses a DSN string, GORM uses separate params or a DSN.
	// Ensure this DSN format matches what golang-migrate/postgres expects.
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName, cfg.DBSSLMode)

	log.Printf("Attempting to run migrations from path: %s with DB URL (password redacted): postgres://%s:***@%s:%s/%s?sslmode=%s",
		migrationsPath, cfg.DBUser, cfg.DBHost, cfg.DBPort, cfg.DBName, cfg.DBSSLMode)

	m, err := migrate.New(migrationsPath, dbURL)
	if err != nil {
		return fmt.Errorf("failed to create new migrate instance: %w. Ensure migrations path and DB URL are correct", err)
	}

	currentVersion, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		log.Printf("Could not get current migration version: %v", err)
	} else if err == migrate.ErrNilVersion {
		log.Println("No migrations have been applied yet.")
	} else {
		log.Printf("Current migration version: %d, Dirty: %t", currentVersion, dirty)
	}
	if dirty {
		log.Println("Warning: Database is in a dirty migration state. Manual intervention may be required.")
		// Optionally, you could try to force a specific version or handle it,
		// but typically this requires manual review.
		// For now, we'll proceed, and m.Up() might fail or fix it.
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	log.Println("Database migrations applied successfully (or no changes needed).")
	srcErr, dbErr := m.Close()
	if srcErr != nil {
		log.Printf("Warning: error closing migration source: %v", srcErr)
	}
	if dbErr != nil {
		log.Printf("Warning: error closing migration database connection: %v", dbErr)
	}
	return nil
}
