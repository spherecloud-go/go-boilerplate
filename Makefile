.PHONY: run build clean test help migrate-up migrate-down migrate-create

# Variables
APP_NAME=testapi
BINARY_NAME=$(APP_NAME)
CMD_PATH=./cmd/api/main.go

# Load .env file for DB_URL. Requires .env to use 'export VAR=val' or manual sourcing.
# This simplified Makefile expects DB_URL to be in the environment or set manually for 'migrate' CLI.
# The Go app itself will load .env for its own DB connection.
# Ensure your .env is sourced or DB_URL is set if you get 'database source not set' errors from migrate CLI.
# Example: export  && make migrate-up
# Or define DB_URL explicitly here if .env parsing in Make is too complex for your setup.

# Fallback if DB_URL not in env (replace with your actual details if needed or ensure .env is sourced)
DB_USER?=youruser
DB_PASSWORD?=yourpassword
DB_HOST?=localhost
DB_PORT?=5432
DB_NAME?=yourdb
DB_SSLMODE?=disable # prefer-verify-full for production
DB_URL?=postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=$(DB_SSLMODE)

MIGRATE_CLI_INSTALLED := $(shell command -v migrate 2> /dev/null)

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
@echo "  Ensure $GOPATH/bin is in your PATH."
@echo "  Migration commands use DB_URL. Ensure it's correctly set (e.g., from .env, or export variables)."
@echo "  Example for sourcing .env (if it doesn't use 'export'): export $ && make migrate-up"


run:
@echo "Running the application (Go app will load .env)..."
@go run $(CMD_PATH)

build:
@echo "Building the application..."
@go build -o $(BINARY_NAME) $(CMD_PATH)
@echo "Build complete: $(BINARY_NAME)"

clean:
@echo "Cleaning build artifacts..."
@if [ -f $(BINARY_NAME) ]; then rm $(BINARY_NAME); fi
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
@echo "And ensure $GOPATH/bin is in your PATH." >&2
@exit 1
endif
@if [ -z "$(DB_URL)" ] || [ "$(DB_URL)" = "postgres://:@::/?sslmode=" ]; then 		echo "Error: DB_URL is not properly set for migrations." >&2 ;		echo "Please ensure your .env file is created from .env.example and filled," >&2 ;		echo "and either source it (e.g., 'export $') or set DB_URL environment variable." >&2 ;		exit 1; 	fi


migrate-up: check_migrate_cli
@echo "Applying migrations up using DB_URL: $(DB_URL)..."
@migrate -database "$(DB_URL)" -path $(MIGRATIONS_PATH) up

migrate-down: check_migrate_cli
@echo "Rolling back last migration using DB_URL: $(DB_URL)..."
@migrate -database "$(DB_URL)" -path $(MIGRATIONS_PATH) down 1

migrate-create: check_migrate_cli
@if [ -z "$(NAME)" ]; then 		echo "Error: Migration NAME is not set. Usage: make migrate-create NAME=your_migration_name"; 		exit 1; 	fi
@echo "Creating migration: $(NAME)..."
@migrate create -ext sql -dir $(MIGRATIONS_PATH) -seq $(NAME)
@echo "Migration files created for $(NAME). Edit them in $(MIGRATIONS_PATH)/"

