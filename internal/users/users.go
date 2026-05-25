package users

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)

// User representa el modelo de usuario en la base de datos.
type User struct {
	ID           int       `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// Credentials define los campos requeridos para registro y login.
type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// TokenResponse representa el cuerpo de respuesta para un login exitoso.
type TokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn string `json:"expires_in"`
}

// Handler contiene las dependencias para las rutas de usuarios.
type Handler struct {
	db        *sql.DB
	jwtSecret []byte
}

// NewHandler inicializa y retorna una instancia de Handler.
func NewHandler(db *sql.DB) (*Handler, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, errors.New("la variable de entorno JWT_SECRET es obligatoria y no está configurada")
	}
	return &Handler{
		db:        db,
		jwtSecret: []byte(secret),
	}, nil
}

// Register maneja la creación de un nuevo usuario en la plataforma.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	// Prevención de DoS: limitar tamaño del cuerpo de la petición a 1MB
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Formato JSON inválido")
		return
	}

	// Validaciones básicas de seguridad
	if !emailRegex.MatchString(creds.Email) {
		h.respondWithError(w, http.StatusBadRequest, "Formato de correo electrónico inválido")
		return
	}
	if len(creds.Password) < 8 {
		h.respondWithError(w, http.StatusBadRequest, "La contraseña debe tener al menos 8 caracteres")
		return
	}

	// Encriptar la contraseña usando bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Error interno de seguridad")
		return
	}

	// Insertar el usuario en la base de datos usando consultas parametrizadas (Evita SQL Injection)
	query := `INSERT INTO users (email, password_hash, created_at) VALUES ($1, $2, $3) RETURNING id, created_at`
	var user User
	err = h.db.QueryRowContext(r.Context(), query, creds.Email, string(hash), time.Now()).Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		// Control de clave duplicada (Postgres error code 23505)
		var pgErr *pq.Error
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			h.respondWithError(w, http.StatusConflict, "El correo electrónico ya se encuentra registrado")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "No se pudo completar el registro")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Usuario registrado exitosamente. Por favor, inicie sesión.",
	})
}

// Login valida las credenciales y genera un token JWT de sesión.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	// Prevención de DoS: limitar tamaño del cuerpo de la petición a 1MB
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Formato JSON inválido")
		return
	}

	// Consulta parametrizada para obtener los datos del usuario
	query := `SELECT id, email, password_hash, created_at FROM users WHERE email = $1 AND is_active = TRUE`
	var user User
	err := h.db.QueryRowContext(r.Context(), query, creds.Email).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)
	if err != nil {
		// Mensaje genérico para prevenir enumeración de usuarios (OWASP compliance)
		h.respondWithError(w, http.StatusUnauthorized, "Credenciales incorrectas")
		return
	}

	// Verificar la contraseña con el hash guardado
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(creds.Password))
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Credenciales incorrectas")
		return
	}

	// Generar el token JWT con expiración de 24 horas y el user_id en claims
	expirationTime := time.Now().Add(24 * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     expirationTime.Unix(),
		"iat":     time.Now().Unix(),
	})

	tokenString, err := token.SignedString(h.jwtSecret)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "No se pudo generar el token de sesión")
		return
	}

	// Configurar cookie de sesión segura bajo directrices OWASP
	http.SetCookie(w, &http.Cookie{
		Name:     "miplazo_session",
		Value:    tokenString,
		Path:     "/",
		MaxAge:   86400, // 24 horas en segundos
		HttpOnly: true,
		Secure:   os.Getenv("ENV") == "production",
		SameSite: http.SameSiteStrictMode, // Mitigación total de ataques CSRF
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Sesión iniciada correctamente",
	})
}

// Logout cierra la sesión del usuario invalidando la cookie miplazo_session.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "miplazo_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Fuerza a que la cookie expire de inmediato
		HttpOnly: true,
		Secure:   os.Getenv("ENV") == "production",
		SameSite: http.SameSiteStrictMode,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Sesión cerrada correctamente",
	})
}

// respondWithError responde de forma consistente con código de estado HTTP y JSON de error.
func (h *Handler) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
