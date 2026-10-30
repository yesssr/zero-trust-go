package nilai

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/yesssr/zero-trust-go/internal/httpx"
	"github.com/yesssr/zero-trust-go/internal/middleware"
)

type Handler struct {
	Repository      *Repository
	TranskripClient *TranskripClient
}

func New(
	repository *Repository,
	transkripClient *TranskripClient,
) *Handler {
	return &Handler{
		Repository:      repository,
		TranskripClient: transkripClient,
	}
}

func (h *Handler) GetGrades(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.UserClaimsFromContext(r.Context())
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

	var grades []Grade

	switch claims.Role {
	case "student":
		grades, err = h.Repository.GetGradesByStudentID(
			r.Context(),
			userID,
		)

	case "lecturer":
		grades, err = h.Repository.GetGradesByLecturerID(
			r.Context(),
			userID,
		)

	case "admin":
		httpx.WriteJSONErr(
			w,
			http.StatusForbidden,
			"Admins cannot access grades through this endpoint",
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

	if err != nil {
		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Failed to retrieve grades",
		)
		return
	}

	httpx.WriteJSON(
		w,
		http.StatusOK,
		"Grades retrieved successfully",
		grades,
	)
}

type UpdateGradeRequest struct {
	Score *float64 `json:"score"`
}

func (h *Handler) UpdateGrade(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.UserClaimsFromContext(r.Context())
	if !ok || claims == nil {
		httpx.WriteJSONErr(
			w,
			http.StatusUnauthorized,
			"User authentication required",
		)
		return
	}

	if claims.Role != "lecturer" {
		httpx.WriteJSONErr(
			w,
			http.StatusForbidden,
			"Only lecturers can update grades",
		)
		return
	}

	lecturerID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		httpx.WriteJSONErr(
			w,
			http.StatusUnauthorized,
			"Invalid user identity",
		)
		return
	}

	gradeID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || gradeID <= 0 {
		httpx.WriteJSONErr(
			w,
			http.StatusBadRequest,
			"Invalid grade ID",
		)
		return
	}

	var req UpdateGradeRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		httpx.WriteJSONErr(
			w,
			http.StatusBadRequest,
			"Invalid request body",
		)
		return
	}

	if req.Score == nil {
		httpx.WriteJSONErr(
			w,
			http.StatusBadRequest,
			"Score is required",
		)
		return
	}

	if *req.Score < 0 || *req.Score > 100 {
		httpx.WriteJSONErr(
			w,
			http.StatusBadRequest,
			"Score must be between 0 and 100",
		)
		return
	}

	from := 1
	to := 21

	if !isWithinAccessHours(time.Now(), from, to) {
		httpx.WriteJSONErr(
			w,
			http.StatusForbidden,
			fmt.Sprintf(
				"Grade updates are only allowed from %d:00 to %d:00 WIB",
				from,
				to,
			),
		)
		return
	}

	updated, err := h.Repository.UpdateGrade(
		r.Context(),
		gradeID,
		lecturerID,
		*req.Score,
	)
	if err != nil {
		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Failed to update grade",
		)
		return
	}

	if !updated {
		httpx.WriteJSONErr(
			w,
			http.StatusConflict,
			"Grade not found, class not assigned to lecturer, or class already finalized",
		)
		return
	}

	httpx.WriteJSON(
		w,
		http.StatusOK,
		"Grade updated successfully",
		map[string]any{
			"id":    gradeID,
			"score": *req.Score,
		},
	)
}

func (h *Handler) FinalizeClass(
	w http.ResponseWriter,
	r *http.Request,
) {
	claims, ok := middleware.UserClaimsFromContext(r.Context())
	if !ok || claims == nil {
		httpx.WriteJSONErr(
			w,
			http.StatusUnauthorized,
			"Unauthorized",
		)
		return
	}

	if claims.Role != "lecturer" {
		httpx.WriteJSONErr(
			w,
			http.StatusForbidden,
			"Only lecturers can finalize classes",
		)
		return
	}

	lecturerID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil || lecturerID <= 0 {
		httpx.WriteJSONErr(
			w,
			http.StatusUnauthorized,
			"Invalid user identity",
		)
		return
	}

	classID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || classID <= 0 {
		httpx.WriteJSONErr(
			w,
			http.StatusBadRequest,
			"Invalid class ID",
		)
		return
	}

	from := 1
	to := 21

	if !isWithinAccessHours(time.Now(), from, to) {
		httpx.WriteJSONErr(
			w,
			http.StatusForbidden,
			fmt.Sprintf(
				"Grade updates are only allowed from %d:00 to %d:00 WIB",
				from,
				to,
			),
		)
		return
	}

	finalized, err := h.Repository.FinalizeClass(
		r.Context(),
		classID,
		lecturerID,
	)
	if err != nil {
		httpx.WriteJSONErr(
			w,
			http.StatusInternalServerError,
			"Failed to finalize class",
		)
		return
	}

	if !finalized {
		httpx.WriteJSONErr(
			w,
			http.StatusConflict,
			"Class not found, not assigned to lecturer, or already finalized",
		)
		return
	}

	syncErr := h.TranskripClient.Sync(r.Context())

	if syncErr != nil {
		httpx.WriteJSON(
			w,
			http.StatusOK,
			"Class finalized, but transcript synchronization failed",
			map[string]any{
				"class_id":          classID,
				"finalized":         true,
				"transcript_synced": false,
			},
		)
		return
	}

	httpx.WriteJSON(
		w,
		http.StatusOK,
		"Class finalized and transcript synchronized successfully",
		map[string]any{
			"class_id":          classID,
			"finalized":         true,
			"transcript_synced": true,
		},
	)
}

func isWithinAccessHours(now time.Time, from, to int) bool {
	location, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		return false
	}

	localTime := now.In(location)
	minutes := localTime.Hour()*60 + localTime.Minute()

	return minutes >= from*60 && minutes < to*60
}
