package services

import (
	"errors"
	"fmt"

	"github.com/spherecloud-go/go-boilerplate/internal/models"
	"github.com/spherecloud-go/go-boilerplate/internal/repositories"

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
