package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/yesssr/zero-trust-go/internal/httpx"
	"github.com/yesssr/zero-trust-go/internal/lib"
)

type serviceClaimsContextKey struct{}

func ServiceClaimsFromContext(ctx context.Context) (*lib.ServiceClaims, bool) {
	claims, ok := ctx.Value(serviceClaimsContextKey{}).(*lib.ServiceClaims)
	return claims, ok && claims != nil
}

func RequireServiceToken(
	jwtSecret string,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		parts := strings.Fields(authHeader)

		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			httpx.WriteJSONErr(
				w,
				http.StatusUnauthorized,
				"Missing or invalid authorization header",
			)
			return
		}

		claims, err := lib.ValidateServiceToken(parts[1], jwtSecret)
		if err != nil {
			httpx.WriteJSONErr(
				w,
				http.StatusUnauthorized,
				"Invalid service token",
			)
			return
		}

		ctx := context.WithValue(r.Context(), serviceClaimsContextKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
