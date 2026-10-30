package transkrip

import (
	"context"
	"database/sql"
)

type Repository struct {
	DB *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		DB: db,
	}
}

func (r *Repository) GetAllStudent(
	ctx context.Context,
	tx *sql.Tx,
) (*sql.Rows, error) {
	rows, err := tx.QueryContext(
		ctx,
		`SELECT id
		 FROM users
		 WHERE role = 'student'`,
	)

	if err != nil {
		return nil, err
	}
	return rows, err
}

func (r *Repository) GetGradeFinalized(
	ctx context.Context,
	tx *sql.Tx,
) (*sql.Rows, error) {
	gradeRows, err := tx.QueryContext(
		ctx,
		`SELECT
			g.student_id,
			c.credits,
			g.score
		 FROM grades g
		 JOIN classes c
			ON c.id = g.class_id
		 JOIN class_students cs
			ON cs.class_id = g.class_id
			AND cs.student_id = g.student_id
		 WHERE c.finalized = 1`,
	)

	if err != nil {
		return nil, err
	}

	return gradeRows, nil
}

func (r *Repository) AddTranscript(
	ctx context.Context,
	tx *sql.Tx,
	studentID int64,
	totalCredits int,
	gpa float64,
) error {
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO transcripts (
			student_id,
			total_credits,
			gpa,
			synced_at
		 )
		 VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(student_id) DO UPDATE SET
			total_credits = excluded.total_credits,
			gpa = excluded.gpa,
			synced_at = CURRENT_TIMESTAMP`,
		studentID,
		totalCredits,
		gpa,
	)

	if err != nil {
		return err
	}

	return nil
}

type Transcript struct {
	NIM          string  `json:"nim"`
	Name         string  `json:"name"`
	TotalCredits int     `json:"total_credits"`
	GPA          float64 `json:"gpa"`
}

func (r *Repository) GetTranscriptByNIM(
	ctx context.Context,
	nim string,
) (*Transcript, error) {
	var transcript Transcript

	err := r.DB.QueryRowContext(
		ctx,
		`SELECT
			u.nim,
			u.name,
			COALESCE(t.total_credits, 0),
			COALESCE(t.gpa, 0)
		 FROM users u
		 LEFT JOIN transcripts t
			ON t.student_id = u.id
		 WHERE u.nim = ?
			AND u.role = 'student'`,
		nim,
	).Scan(
		&transcript.NIM,
		&transcript.Name,
		&transcript.TotalCredits,
		&transcript.GPA,
	)

	if err != nil {
		return nil, err
	}

	return &transcript, nil
}

func (r *Repository) getNIMByUserID(
	ctx context.Context,
	userID int64,
) (string, error) {
	var nim string

	err := r.DB.QueryRowContext(
		ctx,
		`SELECT nim
		 FROM users
		 WHERE id = ?
		   AND role = 'student'`,
		userID,
	).Scan(&nim)

	if err != nil {
		return "", err
	}

	return nim, nil
}
