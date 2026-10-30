package nilai

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

type Grade struct {
	ID          int64   `json:"id"`
	ClassID     int64   `json:"class_id"`
	ClassName   string  `json:"class_name"`
	StudentID   int64   `json:"student_id"`
	StudentNIM  string  `json:"student_nim"`
	StudentName string  `json:"student_name"`
	Score       float64 `json:"score"`
	Finalized   bool    `json:"finalized"`
	Credits     int     `json:"credits"`
}

func (r *Repository) GetGradesByStudentID(
	ctx context.Context,
	studentID int64,
) ([]Grade, error) {
	rows, err := r.DB.QueryContext(
		ctx,
		`SELECT
			g.id,
			c.id,
			c.name,
			u.id,
			u.nim,
			u.name,
			g.score,
			c.finalized,
			c.credits
		 FROM grades g
		 JOIN classes c
			ON c.id = g.class_id
		 JOIN users u
			ON u.id = g.student_id
		 WHERE g.student_id = ?
		 ORDER BY c.name, u.name`,
		studentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	grades := make([]Grade, 0)

	for rows.Next() {
		var grade Grade
		var finalized int

		err := rows.Scan(
			&grade.ID,
			&grade.ClassID,
			&grade.ClassName,
			&grade.StudentID,
			&grade.StudentNIM,
			&grade.StudentName,
			&grade.Score,
			&finalized,
			&grade.Credits,
		)
		if err != nil {
			return nil, err
		}

		grade.Finalized = finalized == 1
		grades = append(grades, grade)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return grades, nil
}

func (r *Repository) GetGradesByLecturerID(
	ctx context.Context,
	lecturerID int64,
) ([]Grade, error) {
	rows, err := r.DB.QueryContext(
		ctx,
		`SELECT
			g.id,
			c.id,
			c.name,
			u.id,
			u.nim,
			u.name,
			g.score,
			c.finalized,
			c.credits
		FROM grades g
		JOIN classes c
			ON c.id = g.class_id
		JOIN users u
			ON u.id = g.student_id
		WHERE c.lecturer_id = ?
		ORDER BY c.name, u.name`,
		lecturerID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	grades := make([]Grade, 0)

	for rows.Next() {
		var grade Grade
		var finalized int

		err := rows.Scan(
			&grade.ID,
			&grade.ClassID,
			&grade.ClassName,
			&grade.StudentID,
			&grade.StudentNIM,
			&grade.StudentName,
			&grade.Score,
			&finalized,
			&grade.Credits,
		)
		if err != nil {
			return nil, err
		}

		grade.Finalized = finalized == 1
		grades = append(grades, grade)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return grades, nil
}

func (r *Repository) UpdateGrade(
	ctx context.Context,
	gradeID int64,
	lecturerID int64,
	score float64,
) (bool, error) {
	result, err := r.DB.ExecContext(
		ctx,
		`UPDATE grades
		 SET score = ?,
		     updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?
		   AND EXISTS (
				SELECT 1
				FROM classes c
				WHERE c.id = grades.class_id
				  AND c.lecturer_id = ?
				  AND c.finalized = 0
		   )`,
		score,
		gradeID,
		lecturerID,
	)
	if err != nil {
		return false, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return rowsAffected > 0, nil
}

func (r *Repository) FinalizeClass(
	ctx context.Context,
	classID int64,
	lecturerID int64,
) (bool, error) {
	result, err := r.DB.ExecContext(
		ctx,
		`UPDATE classes
		 SET finalized = 1
		 WHERE id = ?
		   AND lecturer_id = ?
		   AND finalized = 0`,
		classID,
		lecturerID,
	)
	if err != nil {
		return false, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return rowsAffected > 0, nil
}
