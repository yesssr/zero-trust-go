package lib

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidDevice = errors.New("device is not registered")

func ValidateDevice(
	ctx context.Context,
	db *sql.DB,
	userID int64,
	deviceID string,
) error {
	deviceID = strings.TrimSpace(deviceID)

	if deviceID == "" {
		return ErrInvalidDevice
	}

	var exists bool

	err := db.QueryRowContext(
		ctx,
		`SELECT EXISTS (
			SELECT 1
			FROM devices
			WHERE user_id = ?
			  AND device_id = ?
		)`,
		userID,
		deviceID,
	).Scan(&exists)

	if err != nil {
		return fmt.Errorf("validate device: %w", err)
	}

	if !exists {
		return ErrInvalidDevice
	}

	return nil
}
