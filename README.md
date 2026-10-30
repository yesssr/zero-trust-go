# Zero Trust Architecture - Go

Implementasi sistem **Zero Trust Architecture** menggunakan bahasa Go dengan API Gateway sebagai Policy Enforcement Point (PEP), Policy Engine (PE), autentikasi JWT, validasi perangkat, service-to-service authentication, dan audit logging.

## 1. Arsitektur Sistem

Sistem terdiri dari tiga komponen utama:

| Komponen | Port | Tanggung Jawab |
|---|---:|---|
| API Gateway | `3000` | Entry point, autentikasi, validasi device, policy enforcement, dan reverse proxy |
| Service Nilai | `3001` | Pengelolaan data nilai mahasiswa |
| Service Transkrip | `3002` | Pengelolaan dan sinkronisasi transkrip mahasiswa |

Seluruh request pengguna harus melewati API Gateway. Service Nilai dan Service Transkrip dilindungi menggunakan `X-Gateway-Secret` untuk memastikan request internal berasal dari Gateway.

### Diagram arsitektur

```text
                    CLIENT
                      |
                      v
              +---------------+
              |  API Gateway  |
              |    :3000      |
              +---------------+
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
     Authentication  Device   Policy Engine
          |        Validation      |
          +-----------+------------+
                      |
                      v
                Audit Logging
                      |
             +--------+--------+
             |                 |
             v                 v
      +-------------+   +---------------+
      | Service     |   | Service       |
      | Nilai       |   | Transkrip     |
      | :3001       |   | :3002         |
      +-------------+   +---------------+
             |                 |
             +--------+--------+
                      |
                      v
                 SQLite DB
```

### Alur komunikasi antarlayanan

Service Nilai memperoleh Service Token melalui endpoint autentikasi service pada Gateway, kemudian menggunakan token tersebut untuk meminta sinkronisasi transkrip.

```text
Service Nilai
     |
     v
POST /auth/service
     |
     v
API Gateway
     |
     v
Service Token
     |
     v
POST /transkrip/sinkron
     |
     v
Service Transkrip
```

## 2. Teknologi

- Go
- SQLite
- JWT (JSON Web Token)
- bcrypt
- golang-migrate
- HTTP Reverse Proxy
- API Gateway
- Policy Engine
- Zero Trust Architecture

## 3. Prasyarat

Pastikan perangkat sudah memiliki perangkat lunak berikut:

| Software | Keterangan |
|---|---|
| Go | Bahasa pemrograman utama |
| Git | Clone repository |
| SQLite | Database |
| golang-migrate | Menjalankan database migration |
| Terminal | Menjalankan aplikasi |

### 3.1 Instalasi Go

Unduh dan instal Go melalui:

https://go.dev/dl/

Verifikasi instalasi:

```bash
go version
```

### 3.2 Instalasi Git

Unduh Git melalui:

https://git-scm.com/downloads

Verifikasi instalasi:

```bash
git --version
```

### 3.3 Instalasi SQLite

Unduh SQLite melalui:

https://sqlite.org/download.html

Pastikan SQLite CLI tersedia pada PATH.

Verifikasi instalasi:

```bash
sqlite3 --version
```

### 3.4 Instalasi golang-migrate CLI

`golang-migrate` digunakan untuk menjalankan migration database.

Instal menggunakan perintah:

```bash
go install -tags 'sqlite' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
```

Pastikan direktori binary Go sudah masuk ke PATH.

Periksa lokasi GOPATH:

```bash
go env GOPATH
```

Binary hasil instalasi berada di:

```text
GOPATH/bin
```

**Khusus Windows PowerShell**, tambahkan direktori binary Go ke PATH untuk sesi terminal saat ini:

```powershell
$env:Path += ";$(go env GOPATH)\bin"
```

Untuk penggunaan permanen, tambahkan direktori tersebut melalui Environment Variables Windows.

Verifikasi instalasi:

```bash
migrate -version
```

## 4. Clone Repository

Clone repository:

```bash
git clone https://github.com/yesssr/zero-trust-go.git
```

Masuk ke direktori proyek:

```bash
cd zero-trust-go
```

Unduh dependency:

```bash
go mod download
```

Verifikasi dependency:

```bash
go mod verify
```

## 5. Konfigurasi Environment

Buat file `.env` pada root repository.

```env
# JWT Configuration
JWT_SECRET=ganti-dengan-secret-jwt-yang-aman

# Gateway Configuration
GATEWAY_SECRET=ganti-dengan-secret-internal-yang-aman
GATEWAY_URL=http://localhost:3000

# Database Configuration
DATABASE_PATH=./data/zero-trust.db

# Service Nilai Client Configuration
SERVICE_NILAI_CLIENT_ID=service-nilai
SERVICE_NILAI_CLIENT_SECRET=isi-dengan-secret-service-yang-sesuai-dengan-seed
```

### Keterangan Environment Variable

| Variable | Fungsi |
|---|---|
| `JWT_SECRET` | Secret untuk menandatangani dan memvalidasi JWT |
| `GATEWAY_SECRET` | Secret internal untuk komunikasi Gateway dengan service |
| `GATEWAY_URL` | URL API Gateway yang digunakan Service Nilai |
| `DATABASE_PATH` | Lokasi database SQLite |
| `SERVICE_NILAI_CLIENT_ID` | Identitas Service Nilai |
| `SERVICE_NILAI_CLIENT_SECRET` | Kredensial Service Nilai untuk memperoleh Service Token |

**Penting:**

- Gunakan nilai `JWT_SECRET` yang sama pada komponen yang membutuhkan validasi JWT.
- Gunakan `GATEWAY_SECRET` yang sama pada Gateway, Service Nilai, dan Service Transkrip.
- `SERVICE_NILAI_CLIENT_SECRET` harus sesuai dengan secret yang digunakan ketika data service client di-seed.
- Jangan mengunggah `.env` ke repository publik.

## 6. Database Setup

Sistem menggunakan SQLite sebagai database bersama untuk API Gateway, Service Nilai, dan Service Transkrip.

### 6.1 Membuat direktori database

```bash
mkdir data
```

Jika direktori sudah tersedia, langkah ini dapat dilewati.

### 6.2 Menjalankan migration

Jalankan perintah berikut dari root repository:

```bash
migrate -path ./migrations -database "sqlite://data/zero-trust.db" up
```

Periksa status migration:

```bash
migrate -path ./migrations -database "sqlite://data/zero-trust.db" version
```

Migration membuat struktur tabel yang digunakan sistem:

| Tabel | Fungsi |
|---|---|
| `users` | Menyimpan data pengguna |
| `devices` | Menyimpan perangkat terdaftar |
| `classes` | Menyimpan data kelas |
| `class_students` | Relasi mahasiswa dan kelas |
| `grades` | Menyimpan nilai mahasiswa |
| `refresh_tokens` | Menyimpan refresh token |
| `service_clients` | Menyimpan identitas dan kredensial service |
| `transcripts` | Menyimpan data transkrip |
| `audit_logs` | Menyimpan catatan aktivitas dan keputusan akses |

### 6.3 Seed data

Setelah migration berhasil, pastikan data awal sudah tersedia.

Data awal mencakup:

- Akun admin, dosen, dan mahasiswa.
- Device ID masing-masing pengguna.
- Data kelas.
- Relasi mahasiswa dengan kelas.
- Data nilai mahasiswa.
- Service client `service-nilai`.

Migration hanya membuat struktur tabel. Data awal harus dimasukkan menggunakan mekanisme seed yang tersedia pada repository.

**Catatan:** Pastikan service client menggunakan secret yang sama dengan `SERVICE_NILAI_CLIENT_SECRET` pada file `.env`.

## 7. Data Akun dan Device ID

Berikut akun demo yang digunakan untuk pengujian.

| Role | Email | Password | Device ID |
|---|---|---|---|
| Admin | `admin@example.com` | `AdminDemo123!` | `device-admin-001` |
| Dosen 1 | `lecturer1@example.com` | `DosenDemo123!` | `device-dosen-001` |
| Dosen 2 | `lecturer2@example.com` | `DosenDemo123!` | `device-dosen-002` |
| Mahasiswa 1 | `student1@example.com` | `MahasiswaDemo123!` | `device-mhs-001` |
| Mahasiswa 2 | `student2@example.com` | `MahasiswaDemo123!` | `device-mhs-002` |
| Mahasiswa 3 | `student3@example.com` | `MahasiswaDemo123!` | `device-mhs-003` |

### Data kelas

| Kelas | Dosen | Mahasiswa |
|---|---|---|
| Keamanan Informasi | Dosen 1 | Mahasiswa 1, Mahasiswa 2 |
| Pemrograman Go | Dosen 2 | Mahasiswa 2, Mahasiswa 3 |

### Service Client

| Client ID | Fungsi |
|---|---|
| `service-nilai` | Identitas Service Nilai untuk komunikasi antarlayanan |

Data akun dan device ID tersebut digunakan untuk demonstrasi dan pengujian lokal.

## 8. Menjalankan Aplikasi

Aplikasi memiliki tiga entrypoint yang dijalankan secara terpisah.

Pastikan seluruh konfigurasi environment dan database sudah tersedia sebelum menjalankan aplikasi.

Buka tiga terminal dari root repository.

### 8.1 Terminal 1: API Gateway

Jalankan:

```bash
go run ./cmd/gateway
```

Gateway berjalan pada:

```text
http://localhost:3000
```

Gateway bertindak sebagai entry point seluruh request pengguna.

### 8.2 Terminal 2: Service Nilai

Jalankan:

```bash
go run ./cmd/service-nilai
```

Service Nilai berjalan pada:

```text
http://localhost:3001
```

Service ini menangani pengambilan nilai, pembaruan nilai, dan finalisasi kelas.

### 8.3 Terminal 3: Service Transkrip

Jalankan:

```bash
go run ./cmd/service-transkrip
```

Service Transkrip berjalan pada:

```text
http://localhost:3002
```

Service ini menangani pengambilan dan sinkronisasi transkrip mahasiswa.

### Urutan menjalankan aplikasi

1. Pastikan database sudah dibuat dan di-seed.
2. Jalankan Service Transkrip.
3. Jalankan Service Nilai.
4. Jalankan API Gateway.
5. Lakukan pengujian melalui API Gateway.

Ketiga proses harus tetap berjalan selama aplikasi digunakan.

## 9. API Endpoints

Seluruh endpoint untuk client diakses melalui API Gateway pada port `3000`.

### 9.1 Health Check

| Method | Endpoint | Keterangan |
|---|---|---|
| GET | `/health` | Memeriksa status API Gateway |

### 9.2 Authentication

| Method | Endpoint | Keterangan |
|---|---|---|
| POST | `/auth/login` | Login pengguna |
| POST | `/auth/refresh` | Memperbarui access token |
| POST | `/auth/logout` | Logout dan mencabut refresh token |
| POST | `/auth/service` | Autentikasi service client |

### 9.3 Service Nilai

| Method | Endpoint | Keterangan |
|---|---|---|
| GET | `/nilai` | Mengambil data nilai |
| PUT | `/nilai/{id}` | Memperbarui nilai |
| POST | `/nilai/kelas/{id}/finalisasi` | Finalisasi nilai kelas |

### 9.4 Service Transkrip

| Method | Endpoint | Keterangan |
|---|---|---|
| GET | `/transkrip/{nim}` | Mengambil transkrip mahasiswa |
| POST | `/transkrip/sinkron` | Sinkronisasi transkrip menggunakan Service Token |

## 10. Mekanisme Keamanan

Implementasi Zero Trust pada sistem ini mencakup:

### 10.1 Authentication

Pengguna harus melakukan login dan memperoleh access token JWT yang valid sebelum mengakses resource yang dilindungi.

### 10.2 Device Validation

Gateway memvalidasi `X-Device-ID` terhadap perangkat yang sudah terdaftar pada database.

### 10.3 Policy Engine

Policy Engine mengevaluasi beberapa atribut:

- Identitas pengguna.
- Role pengguna.
- HTTP method.
- Endpoint yang diakses.
- Identitas service untuk komunikasi antarlayanan.

Policy Engine menghasilkan keputusan `allow` atau `deny`.

### 10.4 Policy Enforcement Point

API Gateway bertindak sebagai PEP yang menerapkan keputusan dari Policy Engine sebelum request diteruskan ke service.

### 10.5 Service-to-Service Authentication

Komunikasi Service Nilai dengan Service Transkrip menggunakan Service Token yang diperoleh melalui endpoint autentikasi service pada Gateway.

### 10.6 Gateway Secret

Setiap request internal dari Gateway harus menyertakan header `X-Gateway-Secret` yang valid.

Request langsung ke service tanpa secret yang benar akan ditolak.

### 10.7 Trusted User Identity

Gateway menghapus header identitas pengguna yang dikirim client, kemudian meneruskan identitas berdasarkan JWT yang telah divalidasi.

Dengan demikian, client tidak dapat memanipulasi identitas atau role melalui header HTTP.

### 10.8 Audit Logging

Keputusan akses dan aktivitas autentikasi dicatat dalam tabel `audit_logs`, termasuk:

- Subject.
- Endpoint.
- Device ID.
- Decision.
- Reason.
- Waktu kejadian.

## 11. Pengujian API

Pengujian dapat dilakukan menggunakan Postman atau cURL.

### 11.1 Health Check

```bash
curl -i http://localhost:3000/health
```

### 11.2 Login

```bash
curl -i -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: device-mhs-001" \
  -d '{
    "email": "student1@example.com",
    "password": "MahasiswaDemo123!"
  }'
```

Gunakan access token yang diperoleh dari response login untuk request berikutnya.

### 11.3 Mengambil Nilai

```bash
curl -i http://localhost:3000/nilai \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "X-Device-ID: device-mhs-001"
```

### 11.4 Mengambil Transkrip

```bash
curl -i http://localhost:3000/transkrip/2026001 \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "X-Device-ID: device-mhs-001"
```

### 11.5 Pengujian Tanpa Access Token

```bash
curl -i http://localhost:3000/nilai
```

Hasil yang diharapkan:

```http
HTTP/1.1 401 Unauthorized
```

### 11.6 Pengujian Device Tidak Terdaftar

```bash
curl -i http://localhost:3000/nilai \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "X-Device-ID: device-palsu"
```

Hasil yang diharapkan:

```http
HTTP/1.1 403 Forbidden
```

### 11.7 Pengujian Akses Langsung ke Service

Service Nilai:

```bash
curl -i http://localhost:3001/
```

Service Transkrip:

```bash
curl -i http://localhost:3002/2026001
```

Hasil yang diharapkan:

```http
HTTP/1.1 403 Forbidden
```

Request langsung tanpa `X-Gateway-Secret` yang valid harus ditolak.

## 12. Audit Log

Audit log dapat diperiksa menggunakan SQLite CLI.

```bash
sqlite3 data/zero-trust.db
```

Kemudian jalankan query:

```sql
SELECT
    id,
    occurred_at,
    subject,
    endpoint,
    device_id,
    decision,
    reason
FROM audit_logs
ORDER BY id DESC;
```

Contoh keputusan yang dicatat:

| Decision | Reason |
|---|---|
| allow | `login_success` |
| deny | `invalid_credentials` |
| allow | `grade_read_allowed` |
| allow | `transcript_read_allowed` |
| allow | `service_sync_allowed` |

## 13. Catatan Keamanan

- Jangan membagikan file `.env`.
- Jangan menggunakan secret demo untuk deployment produksi.
- Service Nilai dan Service Transkrip sebaiknya hanya dapat dijangkau melalui jaringan internal.
- Jangan mengekspos port `3001` dan `3002` ke jaringan publik.
- Gunakan HTTPS ketika sistem dijalankan pada lingkungan deployment.
- Lakukan rotasi secret apabila kredensial internal terlanjur terekspos.

## 14. Struktur Repository

```text
zero-trust-go/
├── cmd/
│   ├── gateway/
│   ├── service-nilai/
│   └── service-transkrip/
├── internal/
│   ├── database/
│   ├── domain/
│   │   ├── audit/
│   │   ├── auth/
│   │   ├── nilai/
│   │   ├── policy/
│   │   └── transkrip/
│   ├── httpx/
│   ├── lib/
│   └── middleware/
├── migrations/
├── data/
├── .env
├── .env.example
├── .gitignore
├── go.mod
├── go.sum
└── README.md
```

## 15. Menjalankan Unit Test

Jalankan seluruh unit test dari root repository:

```bash
go test ./...
```

Untuk melihat detail hasil pengujian:

```bash
go test -v ./...
```

---

**Project:** Zero Trust Architecture  
**Language:** Go  
**Database:** SQLite  
**Repository:** https://github.com/yesssr/zero-trust-go
