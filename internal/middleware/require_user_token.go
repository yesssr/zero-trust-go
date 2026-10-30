package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/yesssr/zero-trust-go/internal/httpx"
	"github.com/yesssr/zero-trust-go/internal/lib"
)

type userClaimsContextKey struct{}

func RequireUserToken(
	jwtSecret string,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		parts := strings.Fields(authHeader)

		if len(parts) != 2 ||
			!strings.EqualFold(parts[0], "Bearer") {
			httpx.WriteJSONErr(
				w,
				http.StatusUnauthorized,
				"Missing or invalid authorization header",
			)
			return
		}

		claims, err := lib.ValidateAccessToken(parts[1], jwtSecret)
		if err != nil {
			httpx.WriteJSONErr(
				w,
				http.StatusUnauthorized,
				"Invalid access token",
			)
			return
		}

		ctx := context.WithValue(
			r.Context(),
			userClaimsContextKey{},
			claims,
		)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func UserClaimsFromContext(
	ctx context.Context,
) (*lib.AccessClaims, bool) {
	claims, ok := ctx.Value(userClaimsContextKey{}).(*lib.AccessClaims)
	return claims, ok
}
