package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type Entry struct {
	Subject  string
	Endpoint string
	DeviceID string
	Decision string
	Reason   string
}

type Logger struct {
	DB *sql.DB
}

func (l *Logger) Record(ctx context.Context, entry Entry) error {
	if entry.Decision != "allow" && entry.Decision != "deny" {
		return fmt.Errorf("invalid audit decision: %q", entry.Decision)
	}

	if entry.Endpoint == "" {
		return fmt.Errorf("audit endpoint is required")
	}

	if entry.Reason == "" {
		return fmt.Errorf("audit reason is required")
	}

	_, err := l.DB.ExecContext(
		ctx,
		`INSERT INTO audit_logs (
			occurred_at,
			subject,
			endpoint,
			device_id,
			decision,
			reason
		) VALUES (?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339),
		nullableString(entry.Subject),
		entry.Endpoint,
		nullableString(entry.DeviceID),
		entry.Decision,
		entry.Reason,
	)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}

	return nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}

	return value
}
