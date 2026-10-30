package service_auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/yesssr/zero-trust-go/internal/domain/audit"
	"github.com/yesssr/zero-trust-go/internal/httpx"
	"github.com/yesssr/zero-trust-go/internal/lib"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	JWTSecret             string
	Audit                 *audit.Logger
	ServiceAuthRepository *Repository
}

type ServiceAuthRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type ServiceAuthResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func New(jwtSecret string, audit *audit.Logger, r *Repository) *Handler {
	return &Handler{
		JWTSecret:             jwtSecret,
		Audit:                 audit,
		ServiceAuthRepository: r,
	}
}

func (h *Handler) recordAudit(
	r *http.Request,
	subject string,
	deviceID string,
	decision string,
	reason string,
) error {
	if h.Audit == nil {
		return errors.New("audit logger is not configured")
	}

	return h.Audit.Record(r.Context(), audit.Entry{
		Subject:  subject,
		Endpoint: r.URL.Path,
		DeviceID: deviceID,
		Decision: decision,
		Reason:   reason,
	})
}

func (h *Handler) Authenticate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var req ServiceAuthRequest
	if err := decoder.Decode(&req); err != nil {
		httpx.WriteJSON(
			w,
			http.StatusBadRequest,
			"Invalid request body",
			nil,
		)
		return
	}

	req.ClientID = strings.TrimSpace(req.ClientID)
	req.ClientSecret = strings.TrimSpace(req.ClientSecret)

	if req.ClientID == "" || req.ClientSecret == "" {
		httpx.WriteJSON(
			w,
			http.StatusBadRequest,
			"Client ID and client secret are required",
			nil,
		)
		return
	}

	data, err := h.ServiceAuthRepository.GetSecretByClientID(r.Context(), req.ClientID)
	if err != nil {
		if err == sql.ErrNoRows {
			if auditErr := h.recordAudit(
				r, req.ClientID, "", "deny", "service_client_not_found",
			); auditErr != nil {
				log.Printf("failed to audit service client rejection: %v", auditErr)
			}

			httpx.WriteJSON(
				w,
				http.StatusUnauthorized,
				"Invalid client credentials",
				nil,
			)
			return
		}
		log.Printf("service auth: database query failed: %v", err)
		httpx.WriteJSON(
			w,
			http.StatusInternalServerError,
			"Internal server error",
			nil,
		)
		return
	}

	if data.Active != 1 {
		if auditErr := h.recordAudit(
			r, req.ClientID, "", "deny", "service_client_inactive",
		); auditErr != nil {
			log.Printf("failed to audit service client rejection: %v", auditErr)
		}

		httpx.WriteJSON(
			w,
			http.StatusUnauthorized,
			"Invalid client credentials",
			nil,
		)
		return
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(data.SecretHash),
		[]byte(req.ClientSecret),
	); err != nil {
		if auditErr := h.recordAudit(
			r, req.ClientID, "", "deny", "invalid_client_secret",
		); auditErr != nil {
			log.Printf("failed to audit service client rejection: %v", auditErr)
		}

		httpx.WriteJSON(
			w,
			http.StatusUnauthorized,
			"Invalid client credentials",
			nil,
		)
		return
	}

	token, err := lib.GenerateServiceToken(
		req.ClientID,
		h.JWTSecret,
	)

	if err != nil {
		log.Printf("service auth: token generation failed: %v", err)
		httpx.WriteJSON(
			w,
			http.StatusInternalServerError,
			"Internal server error",
			nil,
		)
		return
	}

	if auditErr := h.recordAudit(
		r, req.ClientID, "", "allow", "service_auth_success",
	); auditErr != nil {
		log.Printf("failed to audit service client rejection: %v", auditErr)
	}

	httpx.WriteJSON(
		w,
		http.StatusOK,
		"Service authentication successful",
		ServiceAuthResponse{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresIn:   int64(lib.ServiceTokenDuration.Seconds()),
		},
	)

}
