package login

import (
	"context"
	"database/sql"
	"errors"
)

type Repository struct {
	DB *sql.DB
}

type GetByEmailRow struct {
	ID           int64
	Email        string
	Role         string
	PasswordHash string
}

var ErrInvalidCredentials = errors.New("invalid email or password")

func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		DB: db,
	}
}

func (r *Repository) GetByEmail(ctx context.Context, email string) (GetByEmailRow, error) {
	var res GetByEmailRow
	err := r.DB.QueryRowContext(
		ctx,
		`SELECT id, email, role, password_hash
		 FROM users
		 WHERE email = ?`,
		email,
	).Scan(
		&res.ID,
		&res.Email,
		&res.Role,
		&res.PasswordHash,
	)
	if err != nil {
		return GetByEmailRow{}, err
	}

	return res, nil
}
