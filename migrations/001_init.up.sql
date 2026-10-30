
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    nim         TEXT UNIQUE,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role        TEXT NOT NULL
                CHECK (role IN ('admin', 'lecturer', 'student')),
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    device_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE (user_id, device_id)
);

CREATE TABLE IF NOT EXISTS classes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    lecturer_id INTEGER NOT NULL,
    finalized   INTEGER NOT NULL DEFAULT 0
                CHECK (finalized IN (0, 1)),

    FOREIGN KEY (lecturer_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS class_students (
    class_id   INTEGER NOT NULL,
    student_id INTEGER NOT NULL,

    PRIMARY KEY (class_id, student_id),
    FOREIGN KEY (class_id) REFERENCES classes(id),
    FOREIGN KEY (student_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS grades (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    class_id    INTEGER NOT NULL,
    student_id  INTEGER NOT NULL,
    score       REAL NOT NULL CHECK (score >= 0 AND score <= 100),
    updated_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (class_id) REFERENCES classes(id),
    FOREIGN KEY (student_id) REFERENCES users(id),
    UNIQUE (class_id, student_id)
);
