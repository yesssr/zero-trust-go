package login

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/yesssr/zero-trust-go/internal/lib"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID    int64
	Email string
	Role  string
}

type Service struct {
	Repo *Repository
}

func NewService(r *Repository) *Service {
	return &Service{
		Repo: r,
	}
}

func (s *Service) Authenticate(
	ctx context.Context,
	email,
	password,
	deviceID string,
) (*User, error) {
	res, err := s.Repo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("query user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(res.PasswordHash),
		[]byte(password),
	); err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := lib.ValidateDevice(ctx, s.Repo.DB, res.ID, deviceID); err != nil {
		return nil, err
	}

	return &User{
		ID:    res.ID,
		Email: res.Email,
		Role:  res.Role,
	}, nil
}
