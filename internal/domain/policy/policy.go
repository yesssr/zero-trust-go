package policy

import (
	"fmt"
	"net/http"
)

type Subject struct {
	ID        string
	Role      string
	TokenType string
}

type Decision struct {
	Allowed bool
	Reason  string
}

type Engine struct {
	ServiceClientID string
}

func NewEngine(serviceClientID string) *Engine {
	return &Engine{
		ServiceClientID: serviceClientID,
	}
}

func (e *Engine) Evaluate(
	subject Subject,
	method string,
	path string,
) Decision {
	if subject.ID == "" {
		return Decision{
			Allowed: false,
			Reason:  "missing_subject",
		}
	}

	// Service-to-service policy
	if subject.TokenType == "service" {
		if subject.ID == e.ServiceClientID &&
			method == http.MethodPost &&
			path == "/transkrip/sinkron" {
			return Decision{
				Allowed: true,
				Reason:  "service_sync_allowed",
			}
		}

		return Decision{
			Allowed: false,
			Reason:  "service_access_denied",
		}
	}

	// User policy
	switch {
	case method == http.MethodGet &&
		(path == "/nilai" || path == "/nilai/") &&
		(subject.Role == "student" || subject.Role == "lecturer"):
		return Decision{
			Allowed: true,
			Reason:  "grade_read_allowed",
		}

	case method == http.MethodPut &&
		isGradeUpdatePath(path) &&
		subject.Role == "lecturer":
		return Decision{
			Allowed: true,
			Reason:  "grade_update_allowed",
		}

	case method == http.MethodPost &&
		isClassFinalizePath(path) &&
		subject.Role == "lecturer":
		return Decision{
			Allowed: true,
			Reason:  "class_finalize_allowed",
		}

	case method == http.MethodGet &&
		isTranscriptPath(path) &&
		(subject.Role == "student" || subject.Role == "admin"):
		return Decision{
			Allowed: true,
			Reason:  "transcript_read_allowed",
		}
	}

	return Decision{
		Allowed: false,
		Reason: fmt.Sprintf(
			"role_%s_not_allowed_for_%s",
			subject.Role,
			method,
		),
	}
}

func isGradeUpdatePath(path string) bool {
	return len(path) > len("/nilai/") &&
		path[:len("/nilai/")] == "/nilai/" &&
		!containsPathSeparator(path[len("/nilai/"):])
}

func isClassFinalizePath(path string) bool {
	const prefix = "/nilai/kelas/"
	const suffix = "/finalisasi"

	if len(path) <= len(prefix)+len(suffix) {
		return false
	}

	if path[:len(prefix)] != prefix {
		return false
	}

	if path[len(path)-len(suffix):] != suffix {
		return false
	}

	classID := path[len(prefix) : len(path)-len(suffix)]
	return !containsPathSeparator(classID)
}

func isTranscriptPath(path string) bool {
	const prefix = "/transkrip/"

	if len(path) <= len(prefix) {
		return false
	}

	if path[:len(prefix)] != prefix {
		return false
	}

	nim := path[len(prefix):]
	return !containsPathSeparator(nim)
}

func containsPathSeparator(value string) bool {
	for _, char := range value {
		if char == '/' {
			return true
		}
	}

	return false
}
