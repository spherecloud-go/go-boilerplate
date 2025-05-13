package routes

import (
	"github.com/spherecloud-go/go-boilerplate/internal/api/handlers"
	"github.com/spherecloud-go/go-boilerplate/internal/api/middleware"
	"github.com/spherecloud-go/go-boilerplate/internal/config"
	"github.com/spherecloud-go/go-boilerplate/internal/repositories"
	"github.com/spherecloud-go/go-boilerplate/internal/services"

	"net/http"

	"github.com/gin-gonic/gin"
	// For Swagger (if you choose to use swaggo)
	// _ "github.com/spherecloud-go/go-boilerplate/docs" // replace with your actual docs path if you generate them
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
		c.JSON(http.StatusOK, gin.H{"status": "UP", "service": "go-boilerplate"})
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
