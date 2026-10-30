package httpx

import (
	"encoding/json"
	"net/http"
)

type responseJSON struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func HealthEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	res := responseJSON{
		Success: true,
		Message: "API is running",
	}

	json.NewEncoder(w).Encode(res)
}

func WriteJSON(w http.ResponseWriter, statusCode int, message string, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	res := responseJSON{
		Success: true,
		Message: message,
		Data:    data,
	}

	json.NewEncoder(w).Encode(res)
}

func WriteJSONErr(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	res := responseJSON{
		Success: false,
		Message: message,
	}

	json.NewEncoder(w).Encode(res)
}
