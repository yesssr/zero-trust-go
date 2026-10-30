package transkrip

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"

	"github.com/yesssr/zero-trust-go/internal/httpx"
	"github.com/yesssr/zero-trust-go/internal/lib"
	"github.com/yesssr/zero-trust-go/internal/middleware"
)

type Handler struct {
	DB         *sql.DB
	Repository *Repository
}

func New(db *sql.DB, r *Repository) *Handler {
	return &Handler{
		DB:         db,
		Repository: r,
	}
}

type SyncResponse struct {
	Count int `json:"count"`
}

type StudentTranscript struct {
	TotalCredits  int
	QualityPoints float64
	GPA           float64
}

func gradePoint(score float64) float64 {
	switch {
	case score >= 85:
		return 4.0
	case score >= 80:
		return 3.5
	case score >= 75:
		return 3.0
	case score >= 70:
		return 2.5
	case score >= 65:
		return 2.0
	case score >= 50:
		return 1.0
	default:
		return 0.0
	}
}

func (h *Handler) Sync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.WriteJSONErr(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx := r.Context()

	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		httpx.WriteJSONErr(w, http.StatusInternalServerError, "Failed to start transaction")
		return
	}
	defer tx.Rollback()

	rows, err := h.Repository.GetAllStudent(ctx, tx)
	if err != nil {
		httpx.WriteJSONErr(w, http.StatusInternalServerError, "Failed to get students")
		return
	}

	transcripts := make(map[int64]*StudentTranscript)

	for rows.Next() {
		var studentID int64
		if err := rows.Scan(&studentID); err != nil {
			rows.Close()
			httpx.WriteJSONErr(w, http.StatusInternalServerError, "Failed to read students")
			return
		}

		transcripts[studentID] = &StudentTranscript{}
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		httpx.WriteJSONErr(w, http.StatusInternalServerError, "Failed to iterate students")
		return
	}
	rows.Close()

	gradeRows, err := h.Repository.GetGradeFinalized(ctx, tx)
	if err != nil {
		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Failed to get finalized grades",
		)
		return
	}

	for gradeRows.Next() {
		var studentID int64
		var credits int
		var score float64

		if err := gradeRows.Scan(&studentID, &credits, &score); err != nil {
			gradeRows.Close()
			httpx.WriteJSONErr(w, http.StatusInternalServerError, "Failed to read grades")
			return
		}

		student, exists := transcripts[studentID]
		if !exists {
			continue
		}

		student.TotalCredits += credits
		student.QualityPoints += float64(credits) * gradePoint(score)
	}

	if err := gradeRows.Err(); err != nil {
		gradeRows.Close()
		httpx.WriteJSONErr(w, http.StatusInternalServerError, "Failed to iterate grades")
		return
	}
	gradeRows.Close()

	for studentID, student := range transcripts {
		if student.TotalCredits > 0 {
			student.GPA = student.QualityPoints / float64(student.TotalCredits)
		}

		err := h.Repository.AddTranscript(
			ctx,
			tx,
			studentID,
			student.TotalCredits,
			student.GPA,
		)
		if err != nil {
			log.Printf("Failed to upsert transcript for student %d: %v", studentID, err)
			httpx.WriteJSONErr(w, http.StatusInternalServerError, "Failed to save transcripts")
			return
		}
	}

	if err := tx.Commit(); err != nil {
		httpx.WriteJSONErr(w, http.StatusInternalServerError, "Failed to commit transcript synchronization")
		return
	}

	httpx.WriteJSON(
		w,
		http.StatusOK,
		"Transcript synchronization completed",
		SyncResponse{Count: len(transcripts)},
	)
}

func (h *Handler) GetByNIM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := middleware.UserClaimsFromContext(ctx)
	if !ok || claims == nil {
		httpx.WriteJSONErr(
			w,
			http.StatusUnauthorized,
			"User authentication required",
		)
		return
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		httpx.WriteJSONErr(
			w,
			http.StatusUnauthorized,
			"Invalid user identity",
		)
		return
	}

	nim := r.PathValue("nim")
	if nim == "" {
		httpx.WriteJSONErr(
			w,
			http.StatusBadRequest,
			"NIM is required",
		)
		return
	}

	switch claims.Role {
	case "student":
		studentNIM, err := h.Repository.getNIMByUserID(ctx, userID)
		if err != nil {
			if err == sql.ErrNoRows {
				httpx.WriteJSONErr(
					w,
					http.StatusForbidden,
					"Student identity not found",
				)
				return
			}

			httpx.WriteJSONErr(
				w,
				http.StatusInternalServerError,
				"Failed to verify student identity",
			)
			return
		}

		if studentNIM != nim {
			httpx.WriteJSONErr(
				w,
				http.StatusForbidden,
				"Students can only access their own transcript",
			)
			return
		}

	case "admin":

	case "lecturer":
		httpx.WriteJSONErr(
			w,
			http.StatusForbidden,
			"Lecturers cannot access transcripts through this endpoint",
		)
		return

	default:
		httpx.WriteJSONErr(
			w,
			http.StatusForbidden,
			"Role is not allowed",
		)
		return
	}

	transcript, err := h.Repository.GetTranscriptByNIM(ctx, nim)
	if err != nil {
		if err == sql.ErrNoRows {
			httpx.WriteJSONErr(
				w,
				http.StatusNotFound,
				"Student transcript not found",
			)
			return
		}

		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Failed to retrieve transcript",
		)
		return
	}

	httpx.WriteJSON(
		w,
		http.StatusOK,
		"Transcript retrieved successfully",
		transcript,
	)
}

var _ *lib.AccessClaims
