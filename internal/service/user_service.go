package service

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/robcowart/ocm/internal/auth"
	"github.com/robcowart/ocm/internal/config"
	"github.com/robcowart/ocm/internal/crypto"
	"github.com/robcowart/ocm/internal/database"
	"github.com/robcowart/ocm/internal/database/models"
)

// UserService handles user operations
type UserService struct {
	db  *database.Database
	cfg *config.Config
}

// NewUserService creates a new user service
func NewUserService(db *database.Database, cfg *config.Config) *UserService {
	return &UserService{
		db:  db,
		cfg: cfg,
	}
}

// CreateUserRequest represents a request to create a user
type CreateUserRequest struct {
	Username string
	Password string
	Role     string
}

// CreateUser creates a new user
func (s *UserService) CreateUser(req *CreateUserRequest) (*models.User, error) {
	// Validate password strength
	if err := auth.ValidatePasswordStrength(req.Password); err != nil {
		return nil, fmt.Errorf("weak password: %w", err)
	}

	// Hash password
	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &models.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		PasswordHash: passwordHash,
		Role:         req.Role,
		CreatedAt:    time.Now(),
	}

	if err := s.db.CreateUser(user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// AuthenticateUser authenticates a user and returns a JWT token
func (s *UserService) AuthenticateUser(username, password string) (string, error) {
	// Get user
	user, err := s.db.GetUserByUsername(username)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("invalid credentials")
		}
		return "", fmt.Errorf("failed to get user: %w", err)
	}

	// Verify password
	if err := auth.VerifyPassword(password, user.PasswordHash); err != nil {
		return "", fmt.Errorf("invalid credentials")
	}

	// Generate JWT token
	token, err := auth.GenerateToken(
		user.ID,
		user.Username,
		user.Role,
		s.cfg.JWT.Secret,
		s.cfg.JWT.Issuer,
		s.cfg.JWT.Expiration,
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	return token, nil
}

// SetupRequest represents initial setup request
type SetupRequest struct {
	Username string
	Password string
}

// SetupResponse contains setup response data
type SetupResponse struct {
	User      *models.User
	MasterKey string
	Token     string
}

// PerformInitialSetup performs first-time setup
func (s *UserService) PerformInitialSetup(req *SetupRequest) (*SetupResponse, error) {
	// Check if setup is already complete
	isComplete, err := s.db.IsSetupComplete()
	if err != nil {
		return nil, fmt.Errorf("failed to check setup status: %w", err)
	}
	if isComplete {
		return nil, fmt.Errorf("setup already complete")
	}

	// Generate master key
	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	// Store master key in database
	masterKeyHex := hex.EncodeToString(masterKey)
	if err := s.db.SetSystemConfig("master_key", masterKeyHex); err != nil {
		return nil, fmt.Errorf("failed to store master key: %w", err)
	}

	// Generate JWT secret if not set
	if s.cfg.JWT.Secret == "" {
		jwtSecret, err := crypto.GenerateMasterKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
		}
		s.cfg.JWT.Secret = hex.EncodeToString(jwtSecret)
		if err := s.db.SetSystemConfig("jwt_secret", s.cfg.JWT.Secret); err != nil {
			return nil, fmt.Errorf("failed to store JWT secret: %w", err)
		}
	}

	// Create admin user
	user, err := s.CreateUser(&CreateUserRequest{
		Username: req.Username,
		Password: req.Password,
		Role:     "admin",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create admin user: %w", err)
	}

	// Generate token
	token, err := auth.GenerateToken(
		user.ID,
		user.Username,
		user.Role,
		s.cfg.JWT.Secret,
		s.cfg.JWT.Issuer,
		s.cfg.JWT.Expiration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &SetupResponse{
		User:      user,
		MasterKey: masterKeyHex,
		Token:     token,
	}, nil
}

// IsSetupComplete checks if initial setup has been completed
func (s *UserService) IsSetupComplete() (bool, error) {
	return s.db.IsSetupComplete()
}

// GetMasterKey retrieves the master key from the database
func (s *UserService) GetMasterKey() ([]byte, error) {
	masterKeyHex, err := s.db.GetSystemConfig("master_key")
	if err != nil {
		return nil, fmt.Errorf("failed to get master key: %w", err)
	}

	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode master key: %w", err)
	}

	return masterKey, nil
}

// LoadJWTSecret loads JWT secret from database if it exists
func (s *UserService) LoadJWTSecret() error {
	secret, err := s.db.GetSystemConfig("jwt_secret")
	if err != nil {
		if err == sql.ErrNoRows {
			return nil // Not an error if not found
		}
		return fmt.Errorf("failed to get JWT secret: %w", err)
	}

	s.cfg.JWT.Secret = secret
	return nil
}
