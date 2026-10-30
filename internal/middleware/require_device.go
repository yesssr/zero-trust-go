package middleware

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/yesssr/zero-trust-go/internal/httpx"
	"github.com/yesssr/zero-trust-go/internal/lib"
)

func RequireDeviceID(
	db *sql.DB,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := UserClaimsFromContext(r.Context())
		if !ok || claims == nil {
			httpx.WriteJSONErr(
				w,
				http.StatusUnauthorized,
				"User authentication required",
			)
			return
		}

		userID, err := strconv.ParseInt(claims.Subject, 10, 64)
		if err != nil || userID <= 0 {
			httpx.WriteJSONErr(
				w,
				http.StatusUnauthorized,
				"Invalid user identity",
			)
			return
		}

		deviceID := strings.TrimSpace(r.Header.Get("X-Device-ID"))
		if deviceID == "" {
			httpx.WriteJSONErr(
				w,
				http.StatusBadRequest,
				"Missing X-Device-ID header",
			)
			return
		}

		err = lib.ValidateDevice(r.Context(), db, userID, deviceID)
		if err != nil {
			if errors.Is(err, lib.ErrInvalidDevice) {
				httpx.WriteJSONErr(
					w,
					http.StatusForbidden,
					"Device is not registered for this user",
				)
				return
			}

			httpx.WriteJSONErr(
				w,
				http.StatusInternalServerError,
				"Failed to validate device",
			)
			return
		}

		next.ServeHTTP(w, r)
	})
}
