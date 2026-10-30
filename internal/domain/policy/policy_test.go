package policy

import (
	"net/http"
	"testing"
)

func TestEvaluate(t *testing.T) {

	clientID := "service-nilai"
	engine := NewEngine(clientID)

	tests := []struct {
		name       string
		subject    Subject
		method     string
		path       string
		wantAllow  bool
		wantReason string
	}{
		{
			name: "student can read grades",
			subject: Subject{
				ID:   "10",
				Role: "student",
			},
			method:     http.MethodGet,
			path:       "/nilai",
			wantAllow:  true,
			wantReason: "grade_read_allowed",
		},
		{
			name: "lecturer can read grades",
			subject: Subject{
				ID:   "20",
				Role: "lecturer",
			},
			method:     http.MethodGet,
			path:       "/nilai",
			wantAllow:  true,
			wantReason: "grade_read_allowed",
		},
		{
			name: "admin cannot read grades",
			subject: Subject{
				ID:   "1",
				Role: "admin",
			},
			method:    http.MethodGet,
			path:      "/nilai",
			wantAllow: false,
		},
		{
			name: "lecturer can update grade",
			subject: Subject{
				ID:   "20",
				Role: "lecturer",
			},
			method:     http.MethodPut,
			path:       "/nilai/10",
			wantAllow:  true,
			wantReason: "grade_update_allowed",
		},
		{
			name: "student cannot update grade",
			subject: Subject{
				ID:   "10",
				Role: "student",
			},
			method:    http.MethodPut,
			path:      "/nilai/10",
			wantAllow: false,
		},
		{
			name: "lecturer can finalize class",
			subject: Subject{
				ID:   "20",
				Role: "lecturer",
			},
			method:     http.MethodPost,
			path:       "/nilai/kelas/1/finalisasi",
			wantAllow:  true,
			wantReason: "class_finalize_allowed",
		},
		{
			name: "student cannot finalize class",
			subject: Subject{
				ID:   "10",
				Role: "student",
			},
			method:    http.MethodPost,
			path:      "/nilai/kelas/1/finalisasi",
			wantAllow: false,
		},
		{
			name: "student can read transcript",
			subject: Subject{
				ID:   "10",
				Role: "student",
			},
			method:     http.MethodGet,
			path:       "/transkrip/12345",
			wantAllow:  true,
			wantReason: "transcript_read_allowed",
		},
		{
			name: "admin can read transcript",
			subject: Subject{
				ID:   "1",
				Role: "admin",
			},
			method:     http.MethodGet,
			path:       "/transkrip/12345",
			wantAllow:  true,
			wantReason: "transcript_read_allowed",
		},
		{
			name: "lecturer cannot read transcript",
			subject: Subject{
				ID:   "20",
				Role: "lecturer",
			},
			method:    http.MethodGet,
			path:      "/transkrip/12345",
			wantAllow: false,
		},
		{
			name: "nilai service can sync transcript",
			subject: Subject{
				ID:        clientID,
				Role:      "service",
				TokenType: "service",
			},
			method:     http.MethodPost,
			path:       "/transkrip/sinkron",
			wantAllow:  true,
			wantReason: "service_sync_allowed",
		},
		{
			name: "other service cannot sync transcript",
			subject: Subject{
				ID:        "service-lain",
				Role:      "service",
				TokenType: "service",
			},
			method:    http.MethodPost,
			path:      "/transkrip/sinkron",
			wantAllow: false,
		},
		{
			name: "missing subject is denied",
			subject: Subject{
				Role: "student",
			},
			method:     http.MethodGet,
			path:       "/nilai",
			wantAllow:  false,
			wantReason: "missing_subject",
		},
		{
			name: "invalid path is denied",
			subject: Subject{
				ID:   "20",
				Role: "lecturer",
			},
			method:    http.MethodPut,
			path:      "/nilai/10/extra",
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.Evaluate(
				tt.subject,
				tt.method,
				tt.path,
			)

			if got.Allowed != tt.wantAllow {
				t.Errorf(
					"Allowed = %v, want %v",
					got.Allowed,
					tt.wantAllow,
				)
			}

			if tt.wantReason != "" && got.Reason != tt.wantReason {
				t.Errorf(
					"Reason = %q, want %q",
					got.Reason,
					tt.wantReason,
				)
			}
		})
	}
}
