package main

import (
	"log"

	"github.com/spherecloud-go/go-boilerplate/internal/api/routes"
	"github.com/spherecloud-go/go-boilerplate/internal/auth"
	"github.com/spherecloud-go/go-boilerplate/internal/config"
	// "github.com/spherecloud-go/go-boilerplate/internal/database"
)

// @title testapi API
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

	// if err := database.Connect(cfg); err != nil {
	// 	log.Fatalf("Failed to connect to database: %v", err)
	// }

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
