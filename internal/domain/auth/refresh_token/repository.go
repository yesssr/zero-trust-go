package refresh_token

import (
	"context"
	"database/sql"
	"errors"

	"github.com/yesssr/zero-trust-go/internal/database"
)

type Repository struct {
	DB *sql.DB
}

type GetByTokenHashRow struct {
	TokenID       int64
	UserID        int64
	ExpiresAtText string
	RevokedAt     sql.NullString
}

var ErrRefreshTokenAlreadyUsed = errors.New("Invalid refresh token")

func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		DB: db,
	}
}

func (r *Repository) GetByTokenHash(
	ctx context.Context,
	tx database.DBTX,
	oldTokenHash string,
) (GetByTokenHashRow, error) {
	var row GetByTokenHashRow
	err := tx.QueryRowContext(
		ctx,
		`SELECT id, user_id, expires_at, revoked_at
		 FROM refresh_tokens
		 WHERE token_hash = ?`,
		oldTokenHash,
	).Scan(
		&row.TokenID,
		&row.UserID,
		&row.ExpiresAtText,
		&row.RevokedAt,
	)

	if err != nil {
		return GetByTokenHashRow{}, err
	}

	return row, nil
}

func (r *Repository) GetUserByRole(
	ctx context.Context,
	tx *sql.Tx,
	userID int64,
) (string, error) {
	var role string
	err := tx.QueryRowContext(
		ctx,
		`SELECT role
		 FROM users
		 WHERE id = ?`,
		userID,
	).Scan(&role)

	if err != nil {
		return "", err
	}

	return role, nil
}

func (r *Repository) AddRefreshToken(
	ctx context.Context,
	dbtx database.DBTX,
	userID int64,
	newRefreshTokenHash string,
	newExpiresAt string,
) error {
	_, err := dbtx.ExecContext(
		ctx,
		`INSERT INTO refresh_tokens (
			user_id,
			token_hash,
			expires_at
		) VALUES (?, ?, ?)`,
		userID,
		newRefreshTokenHash,
		newExpiresAt,
	)

	if err != nil {
		return err
	}

	return nil
}

func (r *Repository) UpdateRefreshToken(
	ctx context.Context,
	tx database.DBTX,
	revokedAt string,
	tokenID int64,
) error {
	query, err := tx.ExecContext(
		ctx,
		`UPDATE refresh_tokens
		 SET revoked_at = ?
		 WHERE id = ?
		   AND revoked_at IS NULL
		   AND expires_at > ?`,
		revokedAt,
		tokenID,
		revokedAt,
	)

	if err != nil {
		return err
	}

	res, err := query.RowsAffected()
	if err != nil {
		return err
	}

	if res != 1 {
		return ErrRefreshTokenAlreadyUsed
	}

	return nil
}

func (r *Repository) RevokeRefreshToken(
	ctx context.Context,
	expirestAt,
	tokenHash string,
) error {
	query, err := r.DB.ExecContext(
		ctx,
		`UPDATE refresh_tokens
		 SET revoked_at = ?
		 WHERE token_hash = ?
		   AND revoked_at IS NULL
		   AND expires_at > ?`,
		expirestAt,
		tokenHash,
		expirestAt,
	)

	if err != nil {
		return err
	}

	res, err := query.RowsAffected()
	if err != nil {
		return err
	}

	if res != 1 {
		return ErrRefreshTokenAlreadyUsed
	}

	return nil
}
