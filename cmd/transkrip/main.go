package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/yesssr/zero-trust-go/internal/database"
	transcript "github.com/yesssr/zero-trust-go/internal/domain/transkrip"
	"github.com/yesssr/zero-trust-go/internal/httpx"
	"github.com/yesssr/zero-trust-go/internal/middleware"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Failed to load .env")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is required")
	}

	gatewaySecret := os.Getenv("GATEWAY_SECRET")
	if gatewaySecret == "" {
		log.Fatal("GATEWAY_SECRET is required")
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

	transcriptRepository := transcript.NewRepository(db)
	transcriptHandler := transcript.New(db, transcriptRepository)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", httpx.HealthEndpoint)

	mux.Handle(
		"POST /sinkron",
		middleware.RequireServiceToken(
			jwtSecret,
			http.HandlerFunc(transcriptHandler.Sync),
		),
	)

	mux.Handle(
		"GET /{nim}",
		middleware.RequireGatewayUser(
			http.HandlerFunc(transcriptHandler.GetByNIM),
		),
	)

	handler := httpx.RequireGatewaySecret(gatewaySecret, mux)

	fmt.Println("service transkrip running on port :3002")
	if err := http.ListenAndServe(":3002", handler); err != nil {
		log.Fatal(err)
		return
	}
}
