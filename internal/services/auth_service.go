package services

import (
	"errors"
	"fmt"

	"github.com/spherecloud-go/go-boilerplate/internal/auth"
	"github.com/spherecloud-go/go-boilerplate/internal/config"
	"github.com/spherecloud-go/go-boilerplate/internal/models"
	"github.com/spherecloud-go/go-boilerplate/internal/repositories"

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
