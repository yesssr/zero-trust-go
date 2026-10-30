package auth

import (
	"database/sql"

	"github.com/yesssr/zero-trust-go/internal/domain/audit"
	login "github.com/yesssr/zero-trust-go/internal/domain/auth/login"
	refresh "github.com/yesssr/zero-trust-go/internal/domain/auth/refresh_token"
	serviceAuth "github.com/yesssr/zero-trust-go/internal/domain/auth/service_auth"
)

type Handler struct {
	LoginHandler        *login.Handler
	RefreshTokenHandler *refresh.Handler
	ServiceAuthHandler  *serviceAuth.Handler
}

func New(
	db *sql.DB,
	jwtSecret string,
	audit *audit.Logger,
	userService *login.Service,
	refreshRepository *refresh.Repository,
	refreshAuthRepository *serviceAuth.Repository,
) *Handler {
	return &Handler{
		LoginHandler:        login.New(db, jwtSecret, audit, userService, refreshRepository),
		RefreshTokenHandler: refresh.New(db, jwtSecret, audit, refreshRepository),
		ServiceAuthHandler:  serviceAuth.New(jwtSecret, audit, refreshAuthRepository),
	}
}
