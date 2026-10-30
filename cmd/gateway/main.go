package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/yesssr/zero-trust-go/internal/database"
	"github.com/yesssr/zero-trust-go/internal/domain/audit"
	"github.com/yesssr/zero-trust-go/internal/domain/auth"
	"github.com/yesssr/zero-trust-go/internal/domain/auth/login"
	"github.com/yesssr/zero-trust-go/internal/domain/auth/refresh_token"
	"github.com/yesssr/zero-trust-go/internal/domain/auth/service_auth"
	"github.com/yesssr/zero-trust-go/internal/domain/policy"
	"github.com/yesssr/zero-trust-go/internal/httpx"
	"github.com/yesssr/zero-trust-go/internal/middleware"
)

func newServiceProxy(
	prefix string,
	target string,
) (http.Handler, error) {
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	gatewaySecret := os.Getenv("GATEWAY_SECRET")
	if gatewaySecret == "" {
		return nil, fmt.Errorf("GATEWAY_SECRET is required")
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(targetURL)

			// Hapus identitas dari client.
			pr.Out.Header.Del("X-User-ID")
			pr.Out.Header.Del("X-User-Role")

			// Inject secret internal Gateway.
			pr.Out.Header.Set("X-Gateway-Secret", gatewaySecret)

			claims, ok := middleware.UserClaimsFromContext(pr.In.Context())
			if ok && claims != nil {
				pr.Out.Header.Set("X-User-ID", claims.Subject)
				pr.Out.Header.Set("X-User-Role", claims.Role)
			}

			pr.Out.URL.Path = strings.TrimPrefix(
				pr.Out.URL.Path,
				prefix,
			)

			if pr.Out.URL.Path == "" {
				pr.Out.URL.Path = "/"
			}

			pr.SetXForwarded()
		},
		ErrorHandler: func(
			w http.ResponseWriter,
			r *http.Request,
			err error,
		) {
			log.Printf("proxy error for %s: %v", r.URL.Path, err)
			httpx.WriteJSONErr(
				w,
				http.StatusBadGateway,
				"service temporary unavailable",
			)
		},
	}

	return proxy, nil
}

func initHandler(db *sql.DB, jwtSecret string, l *audit.Logger) *auth.Handler {
	refreshRepository := refresh_token.NewRepository(db)
	userRepository := login.NewRepository(db)
	serviceAuthRepository := service_auth.NewRepository(db)

	userService := login.NewService(userRepository)
	authHandler := auth.New(
		db,
		jwtSecret,
		l,
		userService,
		refreshRepository,
		serviceAuthRepository,
	)

	return authHandler

}

func requireUserPolicy(
	engine *policy.Engine,
	logger *audit.Logger,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := middleware.UserClaimsFromContext(r.Context())
		if !ok || claims == nil {
			httpx.WriteJSONErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		deviceID := r.Header.Get("X-Device-ID")

		subject := policy.Subject{
			ID:   claims.Subject,
			Role: claims.Role,
		}

		decision := engine.Evaluate(
			subject,
			r.Method,
			r.URL.Path,
		)

		auditDecision := "deny"
		if decision.Allowed {
			auditDecision = "allow"
		}

		middleware.RecordDecision(
			logger,
			r,
			subject.ID,
			deviceID,
			auditDecision,
			decision.Reason,
		)

		if !decision.Allowed {
			httpx.WriteJSONErr(
				w,
				http.StatusForbidden,
				decision.Reason,
			)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func requireServicePolicy(
	engine *policy.Engine,
	logger *audit.Logger,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := middleware.ServiceClaimsFromContext(r.Context())
		if !ok || claims == nil {
			httpx.WriteJSONErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		subject := policy.Subject{
			ID:        claims.Subject,
			Role:      claims.Role,
			TokenType: claims.TokenType,
		}

		decision := engine.Evaluate(
			subject,
			r.Method,
			r.URL.Path,
		)

		auditDecision := "deny"
		if decision.Allowed {
			auditDecision = "allow"
		}

		middleware.RecordDecision(
			logger,
			r,
			subject.ID,
			"",
			auditDecision,
			decision.Reason,
		)

		if !decision.Allowed {
			httpx.WriteJSONErr(
				w,
				http.StatusForbidden,
				decision.Reason,
			)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Failed to load .env")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is required")
	}

	clientID := os.Getenv("SERVICE_NILAI_CLIENT_ID")
	if clientID == "" {
		log.Fatal("SERVICE_NILAI_CLIENT_ID is required")
	}

	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		log.Fatal("DATABASE_PATH is required")
	}

	db, err := database.OpenSQLite(dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	auditLogger := &audit.Logger{
		DB: db,
	}
	policyEngine := policy.NewEngine(clientID)
	mux := http.NewServeMux()

	nilaiProxy, err := newServiceProxy("/nilai", "http://localhost:3001")
	if err != nil {
		log.Fatal(err)
	}

	transkripProxy, err := newServiceProxy("/transkrip", "http://localhost:3002")
	if err != nil {
		log.Fatal(err)
	}

	authHandler := initHandler(db, jwtSecret, auditLogger)

	mux.HandleFunc("GET /health", httpx.HealthEndpoint)

	mux.HandleFunc("POST /auth/login", authHandler.LoginHandler.Login)
	mux.HandleFunc("POST /auth/refresh", authHandler.RefreshTokenHandler.Refresh)
	mux.HandleFunc("POST /auth/logout", authHandler.RefreshTokenHandler.Logout)
	mux.HandleFunc("POST /auth/service", authHandler.ServiceAuthHandler.Authenticate)

	// Service Nilai -> Service Transkrip
	serviceSyncHandler := middleware.RequireServiceToken(
		jwtSecret,
		requireServicePolicy(
			policyEngine,
			auditLogger,
			transkripProxy,
		),
	)

	mux.Handle("POST /transkrip/sinkron", serviceSyncHandler)

	// User -> Service Nilai
	nilaiHandler := middleware.RequireUserToken(
		jwtSecret,
		middleware.RequireDeviceID(
			db,
			requireUserPolicy(
				policyEngine,
				auditLogger,
				nilaiProxy,
			),
		),
	)

	mux.Handle("GET /nilai", nilaiHandler)
	mux.Handle("/nilai/", nilaiHandler)

	// User -> Service Transkrip
	transkripHandler := middleware.RequireUserToken(
		jwtSecret,
		middleware.RequireDeviceID(
			db,
			requireUserPolicy(
				policyEngine,
				auditLogger,
				transkripProxy,
			),
		),
	)

	mux.Handle("GET /transkrip/{nim}", transkripHandler)

	fmt.Println("gateway running on port :3000")
	if err := http.ListenAndServe(":3000", mux); err != nil {
		log.Fatal(err)
	}
}
