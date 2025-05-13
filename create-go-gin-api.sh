#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u
# Pipestatus
set -o pipefail

# --- Configuration ---
DEFAULT_PROJECT_NAME="my-new-go-api"
DEFAULT_DB_USER="youruser"
DEFAULT_DB_PASSWORD="yourpassword"
DEFAULT_DB_NAME="yourdb"
DEFAULT_JWT_SECRET="your-very-strong-secret-key-$(date +%s)" # Add timestamp for uniqueness

# --- Helper Functions ---
log_info() {
    echo -e "\033[32m[INFO]\033[0m $1"
}

log_warning() {
    echo -e "\033[33m[WARN]\033[0m $1"
}

log_error() {
    echo -e "\033[31m[ERROR]\033[0m $1" >&2
    exit 1
}

# --- Main Script ---

# 1. Get Project Name
read -p "Enter project name (Go module path, e.g., github.com/youruser/myapi or just myapi) [${DEFAULT_PROJECT_NAME}]: " PROJECT_NAME
PROJECT_NAME=${PROJECT_NAME:-${DEFAULT_PROJECT_NAME}}

# Extract the last part of the module path for directory name if it's a full path
DIR_NAME=$(basename "${PROJECT_NAME}")

if [ -d "$DIR_NAME" ]; then
    log_error "Directory '$DIR_NAME' already exists. Please remove it or choose a different project name."
fi

log_info "Creating project '$PROJECT_NAME' in directory '$DIR_NAME'..."
mkdir -p "$DIR_NAME"
cd "$DIR_NAME"

# 2. Initialize Go Module
log_info "Initializing Go module..."
go mod init "${PROJECT_NAME}"

# 3. Create Directory Structure
log_info "Creating directory structure..."
mkdir -p cmd/api \
         internal/api/handlers \
         internal/api/middleware \
         internal/api/routes \
         internal/auth \
         internal/config \
         internal/database \
         internal/models \
         internal/repositories \
         internal/services \
         migrations

# 4. Create .gitignore
log_info "Creating .gitignore..."
cat <<-'EOF' > .gitignore
# Binaries for programs and plugins
*.exe
*.exe~
*.dll
*.so
*.dylib

# Test binary, built with `go test -c`
*.test

# Output of the go coverage tool, specifically when used with LiteIDE
*.out

# IDE-specific files
.idea/
.vscode/
*.sublime-project
*.sublime-workspace

# Environment configuration
.env

# Compiled binary
$(basename "${PROJECT_NAME}")
EOF
# Replace placeholder in .gitignore if PROJECT_NAME was a path
sed -i.bak "s|\$(basename \"\${PROJECT_NAME}\")|${DIR_NAME}|g" .gitignore && rm .gitignore.bak


# 5. Create .env.example
log_info "Creating .env.example..."
cat <<-EOF > .env.example
# Application
APP_PORT=8080
GIN_MODE=debug # debug, release, test

# Database (PostgreSQL example)
DB_HOST=localhost
DB_PORT=5432
DB_USER=${DEFAULT_DB_USER}
DB_PASSWORD=${DEFAULT_DB_PASSWORD}
DB_NAME=${DEFAULT_DB_NAME}
DB_SSLMODE=disable # prefer-verify-full for production

# JWT
JWT_SECRET_KEY=${DEFAULT_JWT_SECRET}
JWT_EXPIRATION_HOURS=24
EOF

# 6. Create Makefile
log_info "Creating Makefile..."
cat <<-EOF > Makefile
.PHONY: run build clean test help migrate-up migrate-down migrate-create

# Variables
APP_NAME=${DIR_NAME}
BINARY_NAME=\$(APP_NAME)
CMD_PATH=./cmd/api/main.go

# Load .env file for DB_URL. Requires .env to use 'export VAR=val' or manual sourcing.
# This simplified Makefile expects DB_URL to be in the environment or set manually for 'migrate' CLI.
# The Go app itself will load .env for its own DB connection.
# Ensure your .env is sourced or DB_URL is set if you get 'database source not set' errors from migrate CLI.
# Example: export $(grep -v '^#' .env | xargs) && make migrate-up
# Or define DB_URL explicitly here if .env parsing in Make is too complex for your setup.

# Fallback if DB_URL not in env (replace with your actual details if needed or ensure .env is sourced)
DB_USER?=$(grep DB_USER .env.example | cut -d'=' -f2)
DB_PASSWORD?=$(grep DB_PASSWORD .env.example | cut -d'=' -f2)
DB_HOST?=$(grep DB_HOST .env.example | cut -d'=' -f2)
DB_PORT?=$(grep DB_PORT .env.example | cut -d'=' -f2)
DB_NAME?=$(grep DB_NAME .env.example | cut -d'=' -f2)
DB_SSLMODE?=$(grep DB_SSLMODE .env.example | cut -d'=' -f2)
DB_URL?=postgres://\$(DB_USER):\$(DB_PASSWORD)@\$(DB_HOST):\$(DB_PORT)/\$(DB_NAME)?sslmode=\$(DB_SSLMODE)

MIGRATE_CLI_INSTALLED := \$(shell command -v migrate 2> /dev/null)

# Default target
help:
	@echo "Available commands:"
	@echo "  make run           - Run the application (loads .env automatically)"
	@echo "  make build         - Build the application binary"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make test          - Run tests (implement your tests)"
	@echo "  make migrate-up    - Apply all up migrations (requires migrate CLI and DB_URL)"
	@echo "  make migrate-down  - Rollback the last migration (requires migrate CLI and DB_URL)"
	@echo "  make migrate-create NAME=<migration_name> - Create new migration files (requires migrate CLI)"
	@echo ""
	@echo "Note on migrations: "
	@echo "  The 'migrate' CLI (golang-migrate) needs to be installed."
	@echo "  Install: go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"
	@echo "  Ensure \$GOPATH/bin is in your PATH."
	@echo "  Migration commands use DB_URL. Ensure it's correctly set (e.g., from .env, or export variables)."
	@echo "  Example for sourcing .env (if it doesn't use 'export'): export \$$(grep -v '^#' .env | xargs) && make migrate-up"


run:
	@echo "Running the application (Go app will load .env)..."
	@go run \$(CMD_PATH)

build:
	@echo "Building the application..."
	@go build -o \$(BINARY_NAME) \$(CMD_PATH)
	@echo "Build complete: \$(BINARY_NAME)"

clean:
	@echo "Cleaning build artifacts..."
	@if [ -f \$(BINARY_NAME) ]; then rm \$(BINARY_NAME); fi
	@go clean

test:
	@echo "Running tests (please implement tests)..."
	@go test ./... -v

# Database Migrations
MIGRATIONS_PATH=migrations

check_migrate_cli:
ifndef MIGRATE_CLI_INSTALLED
	@echo "Error: 'migrate' CLI not found. Please install it:" >&2
	@echo "go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest" >&2
	@echo "And ensure \$GOPATH/bin is in your PATH." >&2
	@exit 1
endif
	@if [ -z "\$(DB_URL)" ] || [ "\$(DB_URL)" = "postgres://:@::/?sslmode=" ]; then \
		echo "Error: DB_URL is not properly set for migrations." >&2 ;\
		echo "Please ensure your .env file is created from .env.example and filled," >&2 ;\
		echo "and either source it (e.g., 'export \$$(grep -v '^#' .env | xargs)') or set DB_URL environment variable." >&2 ;\
		exit 1; \
	fi


migrate-up: check_migrate_cli
	@echo "Applying migrations up using DB_URL: \$(DB_URL)..."
	@migrate -database "\$(DB_URL)" -path \$(MIGRATIONS_PATH) up

migrate-down: check_migrate_cli
	@echo "Rolling back last migration using DB_URL: \$(DB_URL)..."
	@migrate -database "\$(DB_URL)" -path \$(MIGRATIONS_PATH) down 1

migrate-create: check_migrate_cli
	@if [ -z "\$(NAME)" ]; then \
		echo "Error: Migration NAME is not set. Usage: make migrate-create NAME=your_migration_name"; \
		exit 1; \
	fi
	@echo "Creating migration: \$(NAME)..."
	@migrate create -ext sql -dir \$(MIGRATIONS_PATH) -seq \$(NAME)
	@echo "Migration files created for \$(NAME). Edit them in \$(MIGRATIONS_PATH)/"

EOF

# 7. Create Go Files (with PROJECT_NAME substituted)

# cmd/api/main.go
log_info "Creating cmd/api/main.go..."
cat <<EOF > cmd/api/main.go
package main

import (
	"log"
	"${PROJECT_NAME}/internal/api/routes"
	"${PROJECT_NAME}/internal/auth"
	"${PROJECT_NAME}/internal/config"
	"${PROJECT_NAME}/internal/database"
)

// @title ${DIR_NAME} API
// @version 1.0
// @description This is a sample server for a Go API.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	auth.InitializeJWT(cfg)

	if err := database.Connect(cfg); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Optional: Run migrations on startup.
	// For production, it's often better to run migrations as a separate step (e.g., 'make migrate-up').
	// If you enable this, ensure 'migrations' folder and DB connection details are correct.
	// if err := database.RunMigrations(cfg); err != nil {
	//  log.Printf("Warning: Failed to run migrations: %v. GORM auto-migrate might still work for initial setup.", err)
	// }


	router := routes.SetupRouter(cfg)

	log.Printf("Server starting on port %s in %s mode", cfg.AppPort, cfg.GinMode)
	if err := router.Run(":" + cfg.AppPort); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
EOF

# internal/config/config.go
log_info "Creating internal/config/config.go..."
cat <<-'EOF' > internal/config/config.go
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
EOF

# internal/database/database.go
log_info "Creating internal/database/database.go..."
cat <<-EOF > internal/database/database.go
package database

import (
	"fmt"
	"log"
	"${PROJECT_NAME}/internal/config"
	"${PROJECT_NAME}/internal/models"

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
EOF

# internal/database/migrate.go
log_info "Creating internal/database/migrate.go..."
cat <<-EOF > internal/database/migrate.go
package database

import (
	"fmt"
	"log"
	"${PROJECT_NAME}/internal/config"

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
EOF

# internal/models/user.go
log_info "Creating internal/models/user.go..."
cat <<-'EOF' > internal/models/user.go
package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	Username  string         `gorm:"uniqueIndex;not null;size:50" json:"username" binding:"required,min=3,max=50"`
	Password  string         `gorm:"not null" json:"-"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	Resources []Resource     `json:"-"`
}

type UserRegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Password string `json:"password" binding:"required,min=6,max=100"`
}

type UserLoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type UserLoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}
EOF

# internal/models/resource.go
log_info "Creating internal/models/resource.go..."
cat <<-'EOF' > internal/models/resource.go
package models

import (
	"time"

	"gorm.io/gorm"
)

type Resource struct {
	ID          uint           `gorm:"primarykey" json:"id"`
	Name        string         `gorm:"not null;size:100" json:"name" binding:"required,min=3,max=100"`
	Description string         `gorm:"size:500" json:"description" binding:"max=500"`
	UserID      uint           `json:"user_id"`
	User        User           `json:"-"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

type CreateResourceRequest struct {
	Name        string `json:"name" binding:"required,min=3,max=100"`
	Description string `json:"description" binding:"max=500"`
}

type UpdateResourceRequest struct {
	Name        *string `json:"name,omitempty" binding:"omitempty,min=3,max=100"`
	Description *string `json:"description,omitempty" binding:"omitempty,max=500"`
}
EOF

# internal/auth/password.go
log_info "Creating internal/auth/password.go..."
cat <<-'EOF' > internal/auth/password.go
package auth

import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
EOF

# internal/auth/jwt.go
log_info "Creating internal/auth/jwt.go..."
cat <<-EOF > internal/auth/jwt.go
package auth

import (
	"fmt"
	"${PROJECT_NAME}/internal/config"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var jwtKey []byte

func InitializeJWT(cfg *config.Config) {
	jwtKey = []byte(cfg.JWTSecretKey)
}

func GenerateJWT(userID uint, username string, cfg *config.Config) (string, error) {
	expirationTime := time.Now().Add(cfg.JWTExpirationTime)
	claims := &Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "${DIR_NAME}",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return tokenString, nil
}

func ValidateJWT(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
EOF

# internal/repositories/user_repository.go
log_info "Creating internal/repositories/user_repository.go..."
cat <<-EOF > internal/repositories/user_repository.go
package repositories

import (
	"${PROJECT_NAME}/internal/database"
	"${PROJECT_NAME}/internal/models"

	"gorm.io/gorm"
)

type UserRepository interface {
	CreateUser(user *models.User) error
	GetUserByUsername(username string) (*models.User, error)
	GetUserByID(id uint) (*models.User, error)
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository() UserRepository {
	return &userRepository{db: database.GetDB()}
}

func (r *userRepository) CreateUser(user *models.User) error {
	return r.db.Create(user).Error
}

func (r *userRepository) GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := r.db.Where("username = ?", username).First(&user).Error
	return &user, err
}

func (r *userRepository) GetUserByID(id uint) (*models.User, error) {
	var user models.User
	err := r.db.First(&user, id).Error
	return &user, err
}
EOF

# internal/repositories/resource_repository.go
log_info "Creating internal/repositories/resource_repository.go..."
cat <<-EOF > internal/repositories/resource_repository.go
package repositories

import (
	"${PROJECT_NAME}/internal/database"
	"${PROJECT_NAME}/internal/models"

	"gorm.io/gorm"
)

type ResourceRepository interface {
	CreateResource(resource *models.Resource) error
	GetResourceByID(id uint, userID uint) (*models.Resource, error)
	GetAllResourcesByUserID(userID uint) ([]models.Resource, error)
	UpdateResource(resource *models.Resource) error
	DeleteResource(id uint, userID uint) error
}

type resourceRepository struct {
	db *gorm.DB
}

func NewResourceRepository() ResourceRepository {
	return &resourceRepository{db: database.GetDB()}
}

func (r *resourceRepository) CreateResource(resource *models.Resource) error {
	return r.db.Create(resource).Error
}

func (r *resourceRepository) GetResourceByID(id uint, userID uint) (*models.Resource, error) {
	var resource models.Resource
	err := r.db.Where("id = ? AND user_id = ?", id, userID).First(&resource).Error
	return &resource, err
}

func (r *resourceRepository) GetAllResourcesByUserID(userID uint) ([]models.Resource, error) {
	var resources []models.Resource
	err := r.db.Where("user_id = ?", userID).Find(&resources).Error
	return resources, err
}

func (r *resourceRepository) UpdateResource(resource *models.Resource) error {
	// Ensure resource.UserID matches for an ownership check if doing partial updates via map
	// or ensure the service layer fetched the resource correctly before calling.
	// .Save() updates all fields, or .Updates() for specific fields.
	return r.db.Save(resource).Error
}

func (r *resourceRepository) DeleteResource(id uint, userID uint) error {
	return r.db.Where("id = ? AND user_id = ?", id, userID).Delete(&models.Resource{}).Error
}
EOF

# internal/services/auth_service.go
log_info "Creating internal/services/auth_service.go..."
cat <<-EOF > internal/services/auth_service.go
package services

import (
	"errors"
	"${PROJECT_NAME}/internal/auth"
	"${PROJECT_NAME}/internal/config"
	"${PROJECT_NAME}/internal/models"
	"${PROJECT_NAME}/internal/repositories"

	"gorm.io/gorm"
)

type AuthService interface {
	Register(req *models.UserRegisterRequest) (*models.User, error)
	Login(req *models.UserLoginRequest, cfg *config.Config) (string, *models.User, error)
}

type authService struct {
	userRepo repositories.UserRepository
}

func NewAuthService(userRepo repositories.UserRepository) AuthService {
	return &authService{userRepo: userRepo}
}

func (s *authService) Register(req *models.UserRegisterRequest) (*models.User, error) {
	_, err := s.userRepo.GetUserByUsername(req.Username)
	if err == nil {
		return nil, errors.New("username already exists")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("database error checking username: %w", err)
	}

	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		Username: req.Username,
		Password: hashedPassword,
	}

	if err := s.userRepo.CreateUser(user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	user.Password = ""
	return user, nil
}

func (s *authService) Login(req *models.UserLoginRequest, cfg *config.Config) (string, *models.User, error) {
	user, err := s.userRepo.GetUserByUsername(req.Username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil, errors.New("invalid username or password")
		}
		return "", nil, fmt.Errorf("database error fetching user: %w", err)
	}

	if !auth.CheckPasswordHash(req.Password, user.Password) {
		return "", nil, errors.New("invalid username or password")
	}

	token, err := auth.GenerateJWT(user.ID, user.Username, cfg)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate token: %w", err)
	}

	user.Password = ""
	return token, user, nil
}
EOF

# internal/services/resource_service.go
log_info "Creating internal/services/resource_service.go..."
cat <<-EOF > internal/services/resource_service.go
package services

import (
	"errors"
	"fmt"
	"${PROJECT_NAME}/internal/models"
	"${PROJECT_NAME}/internal/repositories"

	"gorm.io/gorm"
)

type ResourceService interface {
	CreateResource(req *models.CreateResourceRequest, userID uint) (*models.Resource, error)
	GetResource(id uint, userID uint) (*models.Resource, error)
	ListResources(userID uint) ([]models.Resource, error)
	UpdateResource(id uint, req *models.UpdateResourceRequest, userID uint) (*models.Resource, error)
	DeleteResource(id uint, userID uint) error
}

type resourceService struct {
	resourceRepo repositories.ResourceRepository
}

func NewResourceService(resourceRepo repositories.ResourceRepository) ResourceService {
	return &resourceService{resourceRepo: resourceRepo}
}

func (s *resourceService) CreateResource(req *models.CreateResourceRequest, userID uint) (*models.Resource, error) {
	resource := &models.Resource{
		Name:        req.Name,
		Description: req.Description,
		UserID:      userID,
	}
	if err := s.resourceRepo.CreateResource(resource); err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}
	return resource, nil
}

func (s *resourceService) GetResource(id uint, userID uint) (*models.Resource, error) {
	resource, err := s.resourceRepo.GetResourceByID(id, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("resource not found or access denied")
		}
		return nil, fmt.Errorf("failed to get resource: %w", err)
	}
	return resource, nil
}

func (s *resourceService) ListResources(userID uint) ([]models.Resource, error) {
	resources, err := s.resourceRepo.GetAllResourcesByUserID(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list resources: %w", err)
	}
	return resources, nil
}

func (s *resourceService) UpdateResource(id uint, req *models.UpdateResourceRequest, userID uint) (*models.Resource, error) {
	resource, err := s.resourceRepo.GetResourceByID(id, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("resource not found or access denied for update")
		}
		return nil, fmt.Errorf("failed to get resource for update: %w", err)
	}

	updated := false
	if req.Name != nil && *req.Name != resource.Name {
		resource.Name = *req.Name
		updated = true
	}
	if req.Description != nil && *req.Description != resource.Description {
		resource.Description = *req.Description
		updated = true
	}

	if !updated {
		return resource, nil // No changes
	}

	if err := s.resourceRepo.UpdateResource(resource); err != nil {
		return nil, fmt.Errorf("failed to update resource: %w", err)
	}
	return resource, nil
}

func (s *resourceService) DeleteResource(id uint, userID uint) error {
	// Ensure resource exists and user has permission (checked by repository)
	// Fetching first can confirm existence before delete if specific error messages are needed
	_, err := s.resourceRepo.GetResourceByID(id, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("resource not found or access denied for delete")
		}
		return fmt.Errorf("failed to confirm resource for delete: %w", err)
	}

	if err := s.resourceRepo.DeleteResource(id, userID); err != nil {
		return fmt.Errorf("failed to delete resource: %w", err)
	}
	return nil
}
EOF

# internal/api/middleware/auth_middleware.go
log_info "Creating internal/api/middleware/auth_middleware.go..."
cat <<-EOF > internal/api/middleware/auth_middleware.go
package middleware

import (
	"${PROJECT_NAME}/internal/auth"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	authorizationHeaderKey  = "authorization"
	authorizationTypeBearer = "bearer"
	authorizationPayloadKey = "authorization_payload"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader(authorizationHeaderKey)
		if len(authHeader) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization header is not provided"})
			return
		}

		fields := strings.Fields(authHeader)
		if len(fields) < 2 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			return
		}

		authType := strings.ToLower(fields[0])
		if authType != authorizationTypeBearer {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unsupported authorization type: " + authType})
			return
		}

		accessToken := fields[1]
		claims, err := auth.ValidateJWT(accessToken)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token: " + err.Error()})
			return
		}

		c.Set(authorizationPayloadKey, claims)
		c.Next()
	}
}

func GetAuthClaims(c *gin.Context) (*auth.Claims, bool) {
	val, exists := c.Get(authorizationPayloadKey)
	if !exists {
		return nil, false
	}
	claims, ok := val.(*auth.Claims)
	return claims, ok
}
EOF

# internal/api/handlers/auth_handler.go
log_info "Creating internal/api/handlers/auth_handler.go..."
cat <<-EOF > internal/api/handlers/auth_handler.go
package handlers

import (
	"net/http"
	"strings"

	"${PROJECT_NAME}/internal/config"
	"${PROJECT_NAME}/internal/models"
	"${PROJECT_NAME}/internal/services"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authService services.AuthService
	cfg         *config.Config
}

func NewAuthHandler(authService services.AuthService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{authService: authService, cfg: cfg}
}

// Register godoc
// @Summary Register a new user
// @Description Register a new user with username and password
// @Tags auth
// @Accept  json
// @Produce  json
// @Param   user body models.UserRegisterRequest true "User registration details"
// @Success 201 {object} models.User "Successfully registered"
// @Failure 400 {object} gin.H "Invalid input"
// @Failure 409 {object} gin.H "Username already exists"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req models.UserRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}

	user, err := h.authService.Register(&req)
	if err != nil {
		if strings.Contains(err.Error(), "username already exists") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user: " + err.Error()})
		}
		return
	}

	c.JSON(http.StatusCreated, user)
}

// Login godoc
// @Summary Login a user
// @Description Login a user with username and password, returns a JWT token
// @Tags auth
// @Accept  json
// @Produce  json
// @Param   credentials body models.UserLoginRequest true "User login credentials"
// @Success 200 {object} models.UserLoginResponse "Successfully logged in"
// @Failure 400 {object} gin.H "Invalid input"
// @Failure 401 {object} gin.H "Invalid username or password"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req models.UserLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}

	token, user, err := h.authService.Login(&req, h.cfg)
	if err != nil {
		if strings.Contains(err.Error(), "invalid username or password") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to login: " + err.Error()})
		}
		return
	}
	user.Password = "" // Ensure password hash is not in response

	c.JSON(http.StatusOK, models.UserLoginResponse{Token: token, User: *user})
}
EOF

# internal/api/handlers/resource_handler.go
log_info "Creating internal/api/handlers/resource_handler.go..."
cat <<-EOF > internal/api/handlers/resource_handler.go
package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"${PROJECT_NAME}/internal/api/middleware"
	"${PROJECT_NAME}/internal/models"
	"${PROJECT_NAME}/internal/services"
	"github.com/gin-gonic/gin"
)

type ResourceHandler struct {
	resourceService services.ResourceService
}

func NewResourceHandler(resourceService services.ResourceService) *ResourceHandler {
	return &ResourceHandler{resourceService: resourceService}
}

// CreateResource godoc
// @Summary Create a new resource
// @Description Create a new resource for the authenticated user
// @Tags resources
// @Security ApiKeyAuth
// @Accept  json
// @Produce  json
// @Param   resource body models.CreateResourceRequest true "Resource details"
// @Success 201 {object} models.Resource "Successfully created resource"
// @Failure 400 {object} gin.H "Invalid input"
// @Failure 401 {object} gin.H "Unauthorized"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /resources [post]
func (h *ResourceHandler) CreateResource(c *gin.Context) {
	claims, exists := middleware.GetAuthClaims(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var req models.CreateResourceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}

	resource, err := h.resourceService.CreateResource(&req, claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create resource: " + err.Error()})
		return
	}
	c.JSON(http.StatusCreated, resource)
}

// GetResource godoc
// @Summary Get a resource by ID
// @Description Get a specific resource by its ID, owned by the authenticated user
// @Tags resources
// @Security ApiKeyAuth
// @Produce  json
// @Param   id path int true "Resource ID" Format(uint)
// @Success 200 {object} models.Resource "Successfully retrieved resource"
// @Failure 400 {object} gin.H "Invalid resource ID"
// @Failure 401 {object} gin.H "Unauthorized"
// @Failure 404 {object} gin.H "Resource not found or access denied"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /resources/{id} [get]
func (h *ResourceHandler) GetResource(c *gin.Context) {
	claims, exists := middleware.GetAuthClaims(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid resource ID"})
		return
	}

	resource, err := h.resourceService.GetResource(uint(id), claims.UserID)
	if err != nil {
		if strings.Contains(err.Error(), "not found or access denied") {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get resource: " + err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, resource)
}

// ListResources godoc
// @Summary List all resources for the authenticated user
// @Description List all resources owned by the authenticated user
// @Tags resources
// @Security ApiKeyAuth
// @Produce  json
// @Success 200 {array} models.Resource "Successfully retrieved list of resources"
// @Failure 401 {object} gin.H "Unauthorized"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /resources [get]
func (h *ResourceHandler) ListResources(c *gin.Context) {
	claims, exists := middleware.GetAuthClaims(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	resources, err := h.resourceService.ListResources(claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list resources: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resources)
}

// UpdateResource godoc
// @Summary Update an existing resource
// @Description Update an existing resource owned by the authenticated user
// @Tags resources
// @Security ApiKeyAuth
// @Accept  json
// @Produce  json
// @Param   id path int true "Resource ID" Format(uint)
// @Param   resource body models.UpdateResourceRequest true "Resource update details"
// @Success 200 {object} models.Resource "Successfully updated resource"
// @Failure 400 {object} gin.H "Invalid input or resource ID"
// @Failure 401 {object} gin.H "Unauthorized"
// @Failure 404 {object} gin.H "Resource not found or access denied"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /resources/{id} [put]
func (h *ResourceHandler) UpdateResource(c *gin.Context) {
	claims, exists := middleware.GetAuthClaims(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid resource ID"})
		return
	}

	var req models.UpdateResourceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}
	// Ensure at least one field is provided for update
	if req.Name == nil && req.Description == nil {
		 c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: at least one field (name or description) must be provided for update"})
		 return
	}

	resource, err := h.resourceService.UpdateResource(uint(id), &req, claims.UserID)
	if err != nil {
		if strings.Contains(err.Error(), "not found or access denied") {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update resource: " + err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, resource)
}

// DeleteResource godoc
// @Summary Delete a resource
// @Description Delete a resource by its ID, owned by the authenticated user
// @Tags resources
// @Security ApiKeyAuth
// @Produce  json
// @Param   id path int true "Resource ID" Format(uint)
// @Success 204 "Successfully deleted resource"
// @Failure 400 {object} gin.H "Invalid resource ID"
// @Failure 401 {object} gin.H "Unauthorized"
// @Failure 404 {object} gin.H "Resource not found or access denied"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /resources/{id} [delete]
func (h *ResourceHandler) DeleteResource(c *gin.Context) {
	claims, exists := middleware.GetAuthClaims(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid resource ID"})
		return
	}

	err = h.resourceService.DeleteResource(uint(id), claims.UserID)
	if err != nil {
		if strings.Contains(err.Error(), "not found or access denied") {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete resource: " + err.Error()})
		}
		return
	}
	c.Status(http.StatusNoContent)
}
EOF

# internal/api/routes/routes.go
log_info "Creating internal/api/routes/routes.go..."
cat <<-EOF > internal/api/routes/routes.go
package routes

import (
	"${PROJECT_NAME}/internal/api/handlers"
	"${PROJECT_NAME}/internal/api/middleware"
	"${PROJECT_NAME}/internal/config"
	"${PROJECT_NAME}/internal/repositories"
	"${PROJECT_NAME}/internal/services"

	"github.com/gin-gonic/gin"
	"net/http"

	// For Swagger (if you choose to use swaggo)
	// _ "${PROJECT_NAME}/docs" // replace with your actual docs path if you generate them
	// ginSwagger "github.com/swaggo/gin-swagger"
	// swaggerFiles "github.com/swaggo/files"
)

func SetupRouter(cfg *config.Config) *gin.Engine {
	if cfg.GinMode == "release" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	router := gin.Default()

	// --- CORS Middleware (example, adjust as needed) ---
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent) // 204
			return
		}
		c.Next()
	})

	// --- Repositories ---
	userRepo := repositories.NewUserRepository()
	resourceRepo := repositories.NewResourceRepository()

	// --- Services ---
	authService := services.NewAuthService(userRepo)
	resourceService := services.NewResourceService(resourceRepo)

	// --- Handlers ---
	authHandler := handlers.NewAuthHandler(authService, cfg)
	resourceHandler := handlers.NewResourceHandler(resourceService)

	// --- Swagger (optional, uncomment and configure if using swaggo) ---
	// router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))


	// --- Routes ---
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "UP", "service": "${DIR_NAME}"})
	})

	authRoutes := router.Group("/auth")
	{
		authRoutes.POST("/register", authHandler.Register)
		authRoutes.POST("/login", authHandler.Login)
	}

	resourceRoutes := router.Group("/resources")
	resourceRoutes.Use(middleware.AuthMiddleware())
	{
		resourceRoutes.POST("", resourceHandler.CreateResource)
		resourceRoutes.GET("", resourceHandler.ListResources)
		resourceRoutes.GET("/:id", resourceHandler.GetResource)
		resourceRoutes.PUT("/:id", resourceHandler.UpdateResource)
		resourceRoutes.DELETE("/:id", resourceHandler.DeleteResource)
	}

	return router
}
EOF

# 8. Create Migration Files
log_info "Creating migration files..."
# migrations/000001_create_users_table.up.sql
cat <<-'EOF' > migrations/000001_create_users_table.up.sql
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
EOF

# migrations/000001_create_users_table.down.sql
cat <<-'EOF' > migrations/000001_create_users_table.down.sql
DROP TABLE IF EXISTS users;
EOF

# migrations/000002_create_resources_table.up.sql
cat <<-'EOF' > migrations/000002_create_resources_table.up.sql
CREATE TABLE IF NOT EXISTS resources (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(500),
    user_id INTEGER NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT fk_user
        FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_resources_user_id ON resources(user_id);
EOF

# migrations/000002_create_resources_table.down.sql
cat <<-'EOF' > migrations/000002_create_resources_table.down.sql
DROP TABLE IF EXISTS resources;
EOF


# 9. Install dependencies (go get)
log_info "Fetching Go module dependencies..."
go get -u github.com/gin-gonic/gin
go get -u gorm.io/gorm
go get -u gorm.io/driver/postgres
go get -u github.com/golang-jwt/jwt/v5
go get -u github.com/go-playground/validator/v10
go get -u github.com/joho/godotenv
go get -u golang.org/x/crypto/bcrypt
go get -u github.com/golang-migrate/migrate/v4
# For migrate CLI (user needs to install this separately, but good to have in go.mod for potential programmatic use)
go get -u github.com/golang-migrate/migrate/v4/database/postgres
go get -u github.com/golang-migrate/migrate/v4/source/file

# For Swagger (optional, uncomment if you want to include these and swaggo)
# go get -u github.com/swaggo/gin-swagger
# go get -u github.com/swaggo/files
# go get -u github.com/swaggo/swag/cmd/swag # CLI tool

log_info "Running go mod tidy..."
go mod tidy

# 10. Final Instructions
log_info "Project '${PROJECT_NAME}' created successfully in directory '${DIR_NAME}'!"
echo ""
log_info "Next steps:"
echo "1. cd ${DIR_NAME}"
echo "2. Copy '.env.example' to '.env' and update with your database credentials:"
echo "   cp .env.example .env"
echo "   nano .env  # or your favorite editor"
echo "3. Ensure you have PostgreSQL running and a database created as per your .env settings."
echo "4. Install the 'migrate' CLI if you haven't already:"
echo "   go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"
echo "   (Make sure \$GOPATH/bin or \$GOBIN is in your PATH)"
echo "5. Run database migrations:"
echo "   make migrate-up  # This requires DB_URL to be set, e.g., by sourcing .env: export \$(grep -v '^#' .env | xargs) && make migrate-up"
echo "6. Run the application:"
echo "   make run"
echo "7. (Optional) To generate Swagger docs (if you set it up with swaggo):"
echo "   Install swag CLI: go install github.com/swaggo/swag/cmd/swag@latest"
echo "   Run: swag init -g cmd/api/main.go"
echo "   Then uncomment swagger routes in internal/api/routes/routes.go"
echo ""
log_warning "Remember to review all generated files, especially configuration and Makefile."

# Go back to original directory
cd ..