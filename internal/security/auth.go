package security

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey struct{}

var userIDKey = contextKey{}

// AuthMiddleware es el middleware de autenticación que valida el token JWT en la cookie de sesión.
func AuthMiddleware(jwtSecret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extraer el token de la cookie miplazo_session
		cookie, err := r.Cookie("miplazo_session")
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, "Token de sesión inválido o expirado")
			return
		}

		tokenString := cookie.Value

		// Validar firma y expiración del token JWT
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			// Validar el método de firma
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			respondWithError(w, http.StatusUnauthorized, "Token de sesión inválido o expirado")
			return
		}

		// Extraer claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			respondWithError(w, http.StatusUnauthorized, "Token de sesión inválido o expirado")
			return
		}

		// En JWT, los números decodificados se representan como float64
		userIDFloat, ok := claims["user_id"].(float64)
		if !ok {
			respondWithError(w, http.StatusUnauthorized, "Token de sesión inválido o expirado")
			return
		}

		userID := int(userIDFloat)

		// Guardar user_id de forma segura en el contexto de la petición
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserID de-serializa el user_id del contexto si existe.
func GetUserID(ctx context.Context) (int, bool) {
	userID, ok := ctx.Value(userIDKey).(int)
	return userID, ok
}

// respondWithError responde de forma consistente con formato JSON de error.
func respondWithError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
