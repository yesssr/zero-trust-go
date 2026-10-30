package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/joho/godotenv"
	"github.com/yesssr/zero-trust-go/internal/database"
)

type UserSeed struct {
	NIM      string
	Name     string
	Email    string
	Password string
	Role     string
	DeviceID string
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Failed to load .env")
	}

	clientID := os.Getenv("SERVICE_NILAI_CLIENT_ID")
	if clientID == "" {
		log.Fatal("SERVICE_NILAI_CLIENT_ID is required")
	}

	clientSecret := os.Getenv("SERVICE_NILAI_CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatal("SERVICE_NILAI_CLIENT_SECRET is required")
	}

	db, err := database.OpenSQLite("./data/zero-trust.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := seed(db); err != nil {
		log.Fatal(err)
	}

	if err := seedServiceClient(db, clientID, clientSecret); err != nil {
		log.Fatal(err)
	}

	log.Println("Seed data completed successfully")
}

func seed(db *sql.DB) error {
	users := []UserSeed{
		{
			Name:     "Admin Demo",
			Email:    "admin@example.com",
			Password: "AdminDemo123!",
			Role:     "admin",
			DeviceID: "device-admin-001",
		},
		{
			NIM:      "D001",
			Name:     "Dosen Satu",
			Email:    "dosen1@example.com",
			Password: "DosenDemo123!",
			Role:     "lecturer",
			DeviceID: "device-dosen-001",
		},
		{
			NIM:      "D002",
			Name:     "Dosen Dua",
			Email:    "dosen2@example.com",
			Password: "DosenDemo123!",
			Role:     "lecturer",
			DeviceID: "device-dosen-002",
		},
		{
			NIM:      "2026001",
			Name:     "Mahasiswa Satu",
			Email:    "mhs1@example.com",
			Password: "MahasiswaDemo123!",
			Role:     "student",
			DeviceID: "device-mhs-001",
		},
		{
			NIM:      "2026002",
			Name:     "Mahasiswa Dua",
			Email:    "mhs2@example.com",
			Password: "MahasiswaDemo123!",
			Role:     "student",
			DeviceID: "device-mhs-002",
		},
		{
			NIM:      "2026003",
			Name:     "Mahasiswa Tiga",
			Email:    "mhs3@example.com",
			Password: "MahasiswaDemo123!",
			Role:     "student",
			DeviceID: "device-mhs-003",
		},
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	userIDs := make(map[string]int64)

	for _, user := range users {
		hash, err := bcrypt.GenerateFromPassword(
			[]byte(user.Password),
			bcrypt.DefaultCost,
		)
		if err != nil {
			return fmt.Errorf("hash password for %s: %w", user.Email, err)
		}

		result, err := tx.Exec(`
			INSERT INTO users (nim, name, email, password_hash, role)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(email) DO NOTHING
		`, nullableString(user.NIM), user.Name, user.Email, string(hash), user.Role)
		if err != nil {
			return fmt.Errorf("insert user %s: %w", user.Email, err)
		}

		id, err := result.LastInsertId()
		if err != nil {
			return err
		}

		if id == 0 {
			err = tx.QueryRow(
				"SELECT id FROM users WHERE email = ?",
				user.Email,
			).Scan(&id)
			if err != nil {
				return err
			}
		}

		userIDs[user.Email] = id

		_, err = tx.Exec(`
			INSERT INTO devices (user_id, device_id, name)
			VALUES (?, ?, ?)
			ON CONFLICT(user_id, device_id) DO NOTHING
		`, id, user.DeviceID, "Demo Device")
		if err != nil {
			return fmt.Errorf("insert device for %s: %w", user.Email, err)
		}
	}

	classes := []struct {
		Name     string
		Lecturer string
		Students []string
		Scores   []float64
	}{
		{
			Name:     "Keamanan Informasi",
			Lecturer: "dosen1@example.com",
			Students: []string{
				"mhs1@example.com",
				"mhs2@example.com",
			},
			Scores: []float64{85, 90},
		},
		{
			Name:     "Pemrograman Go",
			Lecturer: "dosen2@example.com",
			Students: []string{
				"mhs2@example.com",
				"mhs3@example.com",
			},
			Scores: []float64{88, 92},
		},
	}

	for _, class := range classes {
		var classID int64

		err := tx.QueryRow(`
			SELECT id FROM classes
			WHERE name = ? AND lecturer_id = ?
		`, class.Name, userIDs[class.Lecturer]).Scan(&classID)

		if err == sql.ErrNoRows {
			result, err := tx.Exec(`
				INSERT INTO classes (name, lecturer_id)
				VALUES (?, ?)
			`, class.Name, userIDs[class.Lecturer])
			if err != nil {
				return err
			}
			classID, err = result.LastInsertId()
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		}

		for i, studentEmail := range class.Students {
			studentID := userIDs[studentEmail]

			_, err := tx.Exec(`
				INSERT INTO class_students (class_id, student_id)
				VALUES (?, ?)
				ON CONFLICT(class_id, student_id) DO NOTHING
			`, classID, studentID)
			if err != nil {
				return err
			}

			_, err = tx.Exec(`
				INSERT INTO grades (class_id, student_id, score)
				VALUES (?, ?, ?)
				ON CONFLICT(class_id, student_id) DO NOTHING
			`, classID, studentID, class.Scores[i])
			if err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

func seedServiceClient(
	db *sql.DB,
	clientID,
	clientSecret string,
) error {
	secretHash, err := bcrypt.GenerateFromPassword(
		[]byte(clientSecret),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return fmt.Errorf("hash service secret: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		`INSERT INTO service_clients
			(client_id, secret_hash, name, active, created_at)
		 VALUES (?, ?, ?, 1, ?)
		 ON CONFLICT(client_id) DO NOTHING`,
		clientID,
		string(secretHash),
		"Service Nilai",
		time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("seed service client: %w", err)
	}

	return tx.Commit()
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
