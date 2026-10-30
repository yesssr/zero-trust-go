package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/yesssr/zero-trust-go/internal/database"
	"github.com/yesssr/zero-trust-go/internal/domain/nilai"
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

	gatewayURL := os.Getenv("GATEWAY_URL")
	if gatewayURL == "" {
		log.Fatal("GATEWAY_URL is required")
	}

	clientID := os.Getenv("SERVICE_NILAI_CLIENT_ID")
	if clientID == "" {
		log.Fatal("SERVICE_NILAI_CLIENT_ID is required")
	}

	clientSecret := os.Getenv("SERVICE_NILAI_CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatal("SERVICE_NILAI_CLIENT_SECRET is required")
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

	mux := http.NewServeMux()

	nilaiRepository := nilai.NewRepository(db)
	transkripClient := nilai.NewTranskripClient(gatewayURL, clientID, clientSecret)
	nilaiHandler := nilai.New(nilaiRepository, transkripClient)

	mux.HandleFunc("GET /health", httpx.HealthEndpoint)

	mux.Handle(
		"GET /",
		middleware.RequireGatewayUser(
			http.HandlerFunc(nilaiHandler.GetGrades),
		),
	)

	mux.Handle(
		"PUT /{id}",
		middleware.RequireGatewayUser(
			http.HandlerFunc(nilaiHandler.UpdateGrade),
		),
	)

	mux.Handle(
		"POST /kelas/{id}/finalisasi",
		middleware.RequireGatewayUser(
			http.HandlerFunc(nilaiHandler.FinalizeClass),
		),
	)

	handler := httpx.RequireGatewaySecret(gatewaySecret, mux)

	fmt.Println("service nilai running on port :3001")
	if err := http.ListenAndServe(":3001", handler); err != nil {
		log.Fatal(err)
		return
	}
}
