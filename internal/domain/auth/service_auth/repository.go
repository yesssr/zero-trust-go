package service_auth

import (
	"context"
	"database/sql"
)

type Repository struct {
	DB *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		DB: db,
	}
}

type GetSecretByClientIDRow struct {
	SecretHash string
	Active     int
}

func (r *Repository) GetSecretByClientID(
	ctx context.Context,
	clientID string,
) (GetSecretByClientIDRow, error) {
	var res GetSecretByClientIDRow
	err := r.DB.QueryRowContext(
		ctx,
		`SELECT secret_hash, active
		 FROM service_clients
		 WHERE client_id = ?`,
		clientID,
	).Scan(&res.SecretHash, &res.Active)

	if err != nil {
		return GetSecretByClientIDRow{}, err
	}

	return res, nil
}
