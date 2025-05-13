package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spherecloud-go/go-boilerplate/internal/config"
	"github.com/spherecloud-go/go-boilerplate/internal/models"
	"github.com/spherecloud-go/go-boilerplate/internal/services"
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
