package config

import (
	"database/sql"
	"fmt"
	"log"
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

	// 🔄 Bucle robusto: Reintenta cada 3 segundos hasta por 10 veces (30 segundos en total)
	// Esto le da tiempo de sobra a Postgres de crear sus archivos en el Droplet
	connected := false
	for i := 1; i <= 10; i++ {
		err = db.Ping()
		if err == nil {
			connected = true
			fmt.Printf(" [DATABASE] Conexión establecida con éxito en el intento %d\n", i)
			break
		}
		fmt.Printf(" [DATABASE] Esperando a PostgreSQL... Intento %d/10 (Error: %v)\n", i, err)
		time.Sleep(3 * time.Second)
	}

	if !connected {
		db.Close()
		return nil, fmt.Errorf("no se pudo conectar a Postgres tras 30 segundos: %w", err)
	}

	// 🔥 Ejecutar la autogeneración nativa de tablas ahora que la conexión es 100% real
	err = buildDatabaseSchema(db)
	if err != nil {
		// 🚨 ESTA LÍNEA ES CRUCIAL: Si Postgres rechaza la query, esto lo imprimirá en los logs de Docker
		log.Printf("❌ ERROR CRÍTICO AL CREAR LAS TABLAS: %v\n", err)
		db.Close()
		return nil, fmt.Errorf("error generando el esquema automático: %w", err)
	} else {
		log.Println("✅ ¡TABLAS AUTOGENERADAS CON ÉXITO EN POSTGRESQL!")
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

// Función que lee los planos y funda las tablas si el disco está en blanco
func buildDatabaseSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		is_active BOOLEAN DEFAULT TRUE NOT NULL
	);

	CREATE TABLE IF NOT EXISTS saving_goals (
		id SERIAL PRIMARY KEY,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		title VARCHAR(255) NOT NULL,
		target_amount NUMERIC(12, 2) NOT NULL,
		current_amount NUMERIC(12, 2) DEFAULT 0.00,
		deadline DATE NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		is_active BOOLEAN DEFAULT TRUE NOT NULL
	);

	CREATE TABLE IF NOT EXISTS transactions (
		id SERIAL PRIMARY KEY,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		type VARCHAR(10) NOT NULL,
		amount NUMERIC(12, 2) NOT NULL,
		description TEXT NOT NULL,
		transaction_date DATE NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		is_active BOOLEAN DEFAULT TRUE NOT NULL
	);

	-- Migración incremental para bases de datos existentes
	ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE NOT NULL;
	ALTER TABLE saving_goals ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE NOT NULL;
	ALTER TABLE transactions ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE NOT NULL;

	-- Índices parciales optimizados para bajo consumo de memoria (WHERE is_active = TRUE)
	CREATE INDEX IF NOT EXISTS idx_users_email_active ON users(email) WHERE is_active = TRUE;
	CREATE INDEX IF NOT EXISTS idx_saving_goals_user_active ON saving_goals(user_id) WHERE is_active = TRUE;
	CREATE INDEX IF NOT EXISTS idx_transactions_user_active ON transactions(user_id) WHERE is_active = TRUE;
	`

	_, err := db.Exec(schema)
	return err
}
