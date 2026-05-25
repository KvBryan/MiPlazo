package router

import (
	"database/sql"
	"net/http"
	"os"
	"time"

	"miplazo/internal/goals"
	"miplazo/internal/security"
	"miplazo/internal/transactions" // <-- 1. Importamos el módulo de transacciones
	"miplazo/internal/users"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRouter(db *sql.DB) http.Handler {
	r := chi.NewRouter()

	// Cargar jwtSecret una sola vez para optimizar memoria en entornos de baja RAM
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(securityHeaders)

	// Inicializar Manejadores (Handlers)
	userHandler, err := users.NewHandler(db)
	if err != nil {
		panic("error crítico al inicializar el handler de usuarios: " + err.Error())
	}
	goalHandler := goals.NewHandler(db)
	txHandler := transactions.NewHandler(db) // <-- 2. Inicializamos el manejador de transacciones

	// Rutas Públicas de Autenticación
	r.Route("/auth", func(r chi.Router) {
		r.Post("/register", userHandler.Register)
		r.Post("/login", userHandler.Login)
		r.Post("/logout", userHandler.Logout)
	})

	// Rutas Protegidas de la API (Requieren JWT)
	r.Route("/api", func(r chi.Router) {
		r.Use(security.AuthMiddleware(jwtSecret))

		// Subgrupo para Metas de Ahorro
		r.Route("/goals", func(r chi.Router) {
			r.Post("/", goalHandler.CreateGoal)
			r.Get("/", goalHandler.GetGoals)
			r.Put("/{id}", goalHandler.UpdateProgress)
			r.Delete("/{id}", goalHandler.DeleteGoal)
		})

		// 🔥 Subgrupo para Transacciones Estilo Excel (/api/transactions)
		r.Route("/transactions", func(r chi.Router) {
			r.Post("/", txHandler.CreateTransaction)       // POST /api/transactions (Registrar ingreso/gasto)
			r.Get("/", txHandler.GetTransactions)         // GET /api/transactions (Ver historial contable)
			r.Put("/{id}", txHandler.UpdateTransaction)   // PUT /api/transactions/1 (Modificar fila)
			r.Delete("/{id}", txHandler.DeleteTransaction) // DELETE /api/transactions/1 (Borrar fila)
		})
	})

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "ok", "message": "MiPlazo API robusta y ligera"}`))
	})

	// Servidor de archivos estáticos para la interfaz de usuario en 'ui/'
	// Captura todas las peticiones restantes y les aplica los middlewares globales (ej: securityHeaders)
	fs := http.FileServer(http.Dir("ui"))
	r.Handle("/*", fs)

	return r
}

// securityHeaders middleware inyecta cabeceras HTTP de seguridad recomendadas por OWASP
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "no-referrer")

		// 🔥 Nueva CSP robusta y flexibilizada para CDNs de UI y peticiones
		w.Header().Set("Content-Security-Policy", 
			"default-src 'self'; "+
			"script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; "+
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
			"font-src 'self' https://fonts.gstatic.com https://unpkg.com; "+
			"connect-src 'self' https://unpkg.com;")

		next.ServeHTTP(w, r)
	})
}