package middleware

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/yesssr/zero-trust-go/internal/httpx"
	"github.com/yesssr/zero-trust-go/internal/lib"
)

func RequireGatewayUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := strings.TrimSpace(r.Header.Get("X-User-ID"))
		role := strings.TrimSpace(r.Header.Get("X-User-Role"))

		id, err := strconv.ParseInt(userID, 10, 64)
		if err != nil || id <= 0 {
			httpx.WriteJSONErr(
				w,
				http.StatusUnauthorized,
				"Invalid gateway user identity",
			)
			return
		}

		switch role {
		case "admin", "lecturer", "student":
		default:
			httpx.WriteJSONErr(
				w,
				http.StatusForbidden,
				"Invalid gateway user role",
			)
			return
		}

		claims := &lib.AccessClaims{
			Role: role,
		}
		claims.Subject = userID

		ctx := context.WithValue(
			r.Context(),
			userClaimsContextKey{},
			claims,
		)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
