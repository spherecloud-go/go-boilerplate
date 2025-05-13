package database

import (
	"fmt"
	"log"

	"github.com/spherecloud-go/go-boilerplate/internal/config"
	"github.com/spherecloud-go/go-boilerplate/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func Connect(cfg *config.Config) error {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=UTC",
		cfg.DBHost, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBPort, cfg.DBSSLMode)

	gormConfig := &gorm.Config{}
	if cfg.GinMode == "debug" {
		gormConfig.Logger = logger.Default.LogMode(logger.Info)
	} else {
		gormConfig.Logger = logger.Default.LogMode(logger.Silent)
	}

	db, err := gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	DB = db
	log.Println("Database connection established.")

	// GORM AutoMigrate:
	// Useful for development for quick schema setup if migration files are not yet run.
	// For production, prefer explicit migration files managed by 'golang-migrate'.
	// This ensures GORM creates tables if they don't exist, respecting its own conventions.
	// It won't alter existing tables if the structure changes; that's what migration files are for.
	err = db.AutoMigrate(&models.User{}, &models.Resource{})
	if err != nil {
		// Log as warning, as migrations might handle schema creation.
		log.Printf("Warning: Failed to auto-migrate database: %v. This might be okay if using migration files.", err)
	} else {
		log.Println("GORM auto-migration check complete (tables created if they didn't exist).")
	}

	return nil
}

func GetDB() *gorm.DB {
	return DB
}
