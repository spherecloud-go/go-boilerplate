package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spherecloud-go/go-boilerplate/internal/api/middleware"
	"github.com/spherecloud-go/go-boilerplate/internal/models"
	"github.com/spherecloud-go/go-boilerplate/internal/services"
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
