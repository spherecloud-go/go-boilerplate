package middleware

import (
	"net/http"
	"strings"

	"github.com/spherecloud-go/go-boilerplate/internal/auth"

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
