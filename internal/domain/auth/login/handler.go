package login

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/yesssr/zero-trust-go/internal/domain/audit"
	"github.com/yesssr/zero-trust-go/internal/domain/auth/refresh_token"
	"github.com/yesssr/zero-trust-go/internal/httpx"
	"github.com/yesssr/zero-trust-go/internal/lib"
)

type Handler struct {
	DB                *sql.DB
	JWTSecret         string
	Audit             *audit.Logger
	Service           *Service
	RefreshRepository *refresh_token.Repository
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

func New(
	db *sql.DB,
	jwtSecret string,
	audit *audit.Logger,
	service *Service,
	refreshRepository *refresh_token.Repository,
) *Handler {
	return &Handler{
		DB:                db,
		JWTSecret:         jwtSecret,
		Audit:             audit,
		Service:           service,
		RefreshRepository: refreshRepository,
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

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var req LoginRequest
	if err := decoder.Decode(&req); err != nil {
		httpx.WriteJSONErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		httpx.WriteJSONErr(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	deviceID := r.Header.Get("X-Device-ID")
	if deviceID == "" {
		httpx.WriteJSONErr(w, http.StatusBadRequest, "X-Device-ID header is required")
		return
	}

	user, err := h.Service.Authenticate(
		r.Context(),
		req.Email,
		req.Password,
		deviceID,
	)

	if err != nil {
		var (
			status int
			reason string
		)

		switch {
		case errors.Is(err, ErrInvalidCredentials):
			status = http.StatusUnauthorized
			reason = "invalid_credentials"

		case errors.Is(err, lib.ErrInvalidDevice):
			status = http.StatusForbidden
			reason = "unregistered_device"

		default:
			log.Printf("login authentication failed: %v", err)
			status = http.StatusInternalServerError
			reason = "authentication_error"
		}

		if auditErr := h.recordAudit(
			r,
			"",
			deviceID,
			"deny",
			reason,
		); auditErr != nil {
			log.Printf("failed to record login audit: %v", auditErr)
			httpx.WriteJSONErr(
				w,
				http.StatusInternalServerError,
				"Internal server error",
			)
			return
		}

		httpx.WriteJSONErr(w, status, err.Error())
		return
	}

	token, err := lib.GenerateAccessToken(user.ID, user.Role, h.JWTSecret)
	if err != nil {
		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Internal server error",
		)
		return
	}

	rToken, rHashToken, err := lib.GenerateRefreshToken()
	if err != nil {
		log.Printf("failed generate refresh token: %v", err)
		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Internal server error",
		)
		return
	}

	expiresAt := time.Now().
		UTC().
		Add(lib.RefreshTokenDuration).
		Format(time.RFC3339)

	err = h.RefreshRepository.AddRefreshToken(
		r.Context(),
		h.DB,
		user.ID,
		rHashToken,
		expiresAt,
	)

	if err != nil {
		log.Printf("failed to store refresh token: %v", err)

		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Failed to complete login",
		)
		return
	}

	if err := h.recordAudit(
		r,
		strconv.FormatInt(user.ID, 10),
		deviceID,
		"allow",
		"login_success",
	); err != nil {
		log.Printf("failed to record login audit: %v", err)
		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Internal server error",
		)
		return
	}

	httpx.WriteJSON(
		w,
		http.StatusOK,
		"login successful",
		LoginResponse{
			AccessToken:  token,
			RefreshToken: rToken,
			TokenType:    "Bearer",
			ExpiresIn:    int64(lib.AccessTokenDuration.Seconds()),
		},
	)
}
