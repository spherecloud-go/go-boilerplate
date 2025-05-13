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
