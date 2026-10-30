package httpx

import (
	"crypto/subtle"
	"net/http"
)

func RequireGatewaySecret(
	secret string,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get("X-Gateway-Secret")

		if secret == "" ||
			subtle.ConstantTimeCompare(
				[]byte(provided),
				[]byte(secret),
			) != 1 {
			WriteJSONErr(w, http.StatusForbidden, "Forbidden")
			return
		}

		next.ServeHTTP(w, r)
	})
}
