package config

import (
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	_ "github.com/lib/pq"
)

// ConnectDB establishes a connection to the PostgreSQL database.
// It securely retrieves credentials from environment variables with defaults,
// configures an optimized connection pool for low-memory environments,
// and verifies the connection with a ping before returning.
func ConnectDB() (*sql.DB, error) {
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "miplazo_user")
	password := getEnv("DB_PASSWORD", "MiPlazoSecurePassword2026")
	dbname := getEnv("DB_NAME", "miplazo_backend")
	sslmode := getEnv("DB_SSLMODE", "disable")

	// Securely construct the connection string (DSN) using net/url.
	// This prevents DSN injection vulnerabilities (OWASP compliance)
	// by properly URL-encoding special characters in credentials.
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   net.JoinHostPort(host, port),
		Path:   "/" + dbname,
	}
	q := u.Query()
	q.Set("sslmode", sslmode)
	u.RawQuery = q.Encode()

	db, err := sql.Open("postgres", u.String())
	if err != nil {
		return nil, fmt.Errorf("error opening database connection: %w", err)
	}

	// Optimize connection pool for low RAM (512MB)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Ensure the connection is actually alive
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("error pinging database: %w", err)
	}

	return db, nil
}

// getEnv returns the value of an environment variable or a default value if empty.
func getEnv(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}
