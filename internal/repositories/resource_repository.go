package repositories

import (
	"github.com/spherecloud-go/go-boilerplate/internal/database"
	"github.com/spherecloud-go/go-boilerplate/internal/models"

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
