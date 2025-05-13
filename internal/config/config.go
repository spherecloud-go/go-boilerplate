package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	AppPort           string
	GinMode           string
	DBHost            string
	DBPort            string
	DBUser            string
	DBPassword        string
	DBName            string
	DBSSLMode         string
	JWTSecretKey      string
	JWTExpirationTime time.Duration
}

func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found or error loading it, relying on environment variables")
	}

	appPort := getEnv("APP_PORT", "8080")
	ginMode := getEnv("GIN_MODE", "debug")

	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "user")
	dbPassword := getEnv("DB_PASSWORD", "password")
	dbName := getEnv("DB_NAME", "mydb")
	dbSSLMode := getEnv("DB_SSLMODE", "disable")

	jwtSecret := getEnv("JWT_SECRET_KEY", "supersecret")
	jwtExpHoursStr := getEnv("JWT_EXPIRATION_HOURS", "24")
	jwtExpHours, err := strconv.Atoi(jwtExpHoursStr)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_EXPIRATION_HOURS: %w", err)
	}

	return &Config{
		AppPort:           appPort,
		GinMode:           ginMode,
		DBHost:            dbHost,
		DBPort:            dbPort,
		DBUser:            dbUser,
		DBPassword:        dbPassword,
		DBName:            dbName,
		DBSSLMode:         dbSSLMode,
		JWTSecretKey:      jwtSecret,
		JWTExpirationTime: time.Hour * time.Duration(jwtExpHours),
	}, nil
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
