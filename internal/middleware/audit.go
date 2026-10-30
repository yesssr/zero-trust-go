package middleware

import (
	"log"
	"net/http"

	"github.com/yesssr/zero-trust-go/internal/domain/audit"
)

func RecordDecision(
	logger *audit.Logger,
	r *http.Request,
	subject string,
	deviceID string,
	decision string,
	reason string,
) {
	if logger == nil {
		log.Printf("audit logger is nil: %s %s", r.Method, r.URL.Path)
		return
	}

	err := logger.Record(r.Context(), audit.Entry{
		Subject:  subject,
		Endpoint: r.Method + " " + r.URL.Path,
		DeviceID: deviceID,
		Decision: decision,
		Reason:   reason,
	})

	if err != nil {
		log.Printf("failed to record gateway audit: %v", err)
	}
}
