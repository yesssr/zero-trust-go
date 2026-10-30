package refresh_token

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yesssr/zero-trust-go/internal/domain/audit"
	"github.com/yesssr/zero-trust-go/internal/httpx"
	"github.com/yesssr/zero-trust-go/internal/lib"
)

type Handler struct {
	DB         *sql.DB
	JWTSecret  string
	Audit      *audit.Logger
	Repository *Repository
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func New(
	db *sql.DB,
	jwtSecret string,
	audit *audit.Logger,
	repository *Repository,
) *Handler {
	return &Handler{
		DB:         db,
		JWTSecret:  jwtSecret,
		Audit:      audit,
		Repository: repository,
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

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var req RefreshRequest
	if err := decoder.Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	if strings.TrimSpace(req.RefreshToken) == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, "Refresh token is required", nil)
		return
	}

	ctx := r.Context()
	deviceID := strings.TrimSpace(r.Header.Get("X-Device-ID"))

	tokenHash := lib.HashRefreshToken(req.RefreshToken)
	user, err := h.Repository.GetByTokenHash(ctx, h.DB, tokenHash)
	if err != nil {
		status := http.StatusInternalServerError
		msg := "Internal server error"

		if errors.Is(err, sql.ErrNoRows) {
			status = http.StatusUnauthorized
			msg = "Already logout"
		} else {
			log.Printf("logout: failed to find token owner: %v", err)
		}

		httpx.WriteJSONErr(
			w,
			status,
			msg,
		)
		return
	}

	subject := strconv.FormatInt(user.UserID, 10)
	now := time.Now().UTC().Format(time.RFC3339)

	err = h.Repository.RevokeRefreshToken(ctx, now, tokenHash)
	if err != nil {
		status := http.StatusInternalServerError
		msg := "Failed to refresh token"

		if errors.Is(err, ErrRefreshTokenAlreadyUsed) {
			if auditErr := h.recordAudit(
				r, "", deviceID, "deny", "refresh_token_already_used",
			); auditErr != nil {
				log.Printf("failed to audit refresh rejection: %v", auditErr)
			}

			status = http.StatusUnauthorized
			msg = "Invalid refresh token"

		} else {
			log.Printf("failed to revoke old refresh token: %v", err)
		}
		httpx.WriteJSONErr(
			w,
			status,
			msg,
		)
		return
	}

	if err := h.recordAudit(
		r,
		subject,
		deviceID,
		"allow",
		"logout_success",
	); err != nil {
		log.Printf("logout: failed to record success audit: %v", err)
	}

	httpx.WriteJSON(
		w,
		http.StatusOK,
		"Logout successful",
		nil,
	)
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var req RefreshRequest
	if err := decoder.Decode(&req); err != nil {
		httpx.WriteJSONErr(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if strings.TrimSpace(req.RefreshToken) == "" {
		httpx.WriteJSONErr(w, http.StatusBadRequest, "Refresh token is required")
		return
	}

	deviceID := strings.TrimSpace(r.Header.Get("X-Device-ID"))

	now := time.Now().UTC()
	nowString := now.Format(time.RFC3339)
	oldTokenHash := lib.HashRefreshToken(req.RefreshToken)

	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		log.Printf("failed to begin refresh transaction: %v", err)
		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Failed to refresh token",
		)
		return
	}
	defer tx.Rollback()

	res, err := h.Repository.GetByTokenHash(r.Context(), tx, oldTokenHash)

	if errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()

		if auditErr := h.recordAudit(
			r, "", deviceID, "deny", "invalid_refresh_token",
		); auditErr != nil {
			log.Printf("failed to audit refresh rejection: %v", auditErr)
		}

		httpx.WriteJSONErr(
			w,
			http.StatusUnauthorized,
			"Invalid refresh token",
		)
		return
	}

	if err != nil {
		log.Printf("failed to query refresh token: %v", err)

		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Failed to refresh token",
		)
		return
	}

	expiresAt, err := time.Parse(time.RFC3339, res.ExpiresAtText)
	if err != nil {
		log.Printf("invalid refresh token expiry in database")

		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Failed to refresh token",
		)
		return
	}

	if res.RevokedAt.Valid || !now.Before(expiresAt) {
		_ = tx.Rollback()

		if auditErr := h.recordAudit(
			r, "", deviceID, "deny", "expired_or_revoked_refresh_token",
		); auditErr != nil {
			log.Printf("failed to audit refresh rejection: %v", auditErr)
		}

		httpx.WriteJSONErr(
			w,
			http.StatusUnauthorized,
			"Invalid refresh token",
		)
		return
	}

	role, err := h.Repository.GetUserByRole(r.Context(), tx, res.UserID)

	if errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()

		if auditErr := h.recordAudit(
			r,
			"",
			deviceID,
			"deny",
			"refresh_token_owner_not_found",
		); auditErr != nil {
			log.Printf("failed to audit refresh rejection: %v", auditErr)
		}

		httpx.WriteJSONErr(
			w,
			http.StatusUnauthorized,
			"Invalid refresh token",
		)
		return
	}

	if err != nil {
		log.Printf("failed to query refresh token owner: %v", err)

		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Failed to refresh token",
		)
		return
	}

	accessToken, err := lib.GenerateAccessToken(
		res.UserID,
		role,
		h.JWTSecret,
	)

	if err != nil {
		log.Printf("failed to generate access token: %v", err)

		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Failed to refresh token",
		)
		return
	}

	newRefreshToken, newRefreshTokenHash, err := lib.GenerateRefreshToken()
	if err != nil {
		log.Printf("failed to generate refresh token: %v", err)

		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Failed to refresh token",
		)
		return
	}

	err = h.Repository.UpdateRefreshToken(r.Context(), tx, nowString, res.TokenID)
	if err != nil {
		status := http.StatusInternalServerError
		msg := "Failed to refresh token"

		if errors.Is(err, ErrRefreshTokenAlreadyUsed) {
			_ = tx.Rollback()

			if auditErr := h.recordAudit(
				r, "", deviceID, "deny", "refresh_token_already_used",
			); auditErr != nil {
				log.Printf("failed to audit refresh rejection: %v", auditErr)
			}

			status = http.StatusUnauthorized
			msg = "Invalid refresh token"

		} else {
			log.Printf("failed to revoke old refresh token: %v", err)
		}
		httpx.WriteJSONErr(
			w,
			status,
			msg,
		)
		return
	}

	newExpiresAt := now.Add(lib.RefreshTokenDuration).
		Format(time.RFC3339)

	err = h.Repository.AddRefreshToken(r.Context(), tx, res.UserID, newRefreshTokenHash, newExpiresAt)
	if err != nil {
		log.Printf("failed to store rotated refresh token: %v", err)

		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Failed to refresh token",
		)
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("failed to commit refresh transaction: %v", err)

		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Failed to refresh token",
		)
		return
	}

	if auditErr := h.recordAudit(
		r,
		strconv.FormatInt(res.UserID, 10),
		deviceID,
		"allow",
		"refresh_success",
	); auditErr != nil {
		log.Printf("failed to audit successful refresh: %v", auditErr)
	}

	httpx.WriteJSON(
		w,
		http.StatusOK,
		"Token refreshed successfully",
		map[string]any{
			"access_token":  accessToken,
			"refresh_token": newRefreshToken,
			"token_type":    "Bearer",
			"expires_in":    int(lib.AccessTokenDuration.Seconds()),
		},
	)
}
