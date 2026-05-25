package security

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type ipLimiter struct {
	mu     sync.Mutex
	ips    map[string]*ipState
	rate   int
	window time.Duration
}

type ipState struct {
	windowStart time.Time
	requests    int
	lastSeen    time.Time
}

// NewIPLimiter crea una nueva instancia del limitador de tasa
func NewIPLimiter(rate int, window time.Duration) *ipLimiter {
	limiter := &ipLimiter{
		ips:    make(map[string]*ipState),
		rate:   rate,
		window: window,
	}
	go limiter.cleanupLoop()
	return limiter
}

// Limit es el middleware que intercepta las peticiones y evalúa la tasa de la IP
func (l *ipLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		// Detectar la IP real de los clientes si están detrás de un proxy (Caddy/Nginx)
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ip = forwarded
		} else if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			ip = realIP
		}

		l.mu.Lock()
		state, exists := l.ips[ip]
		now := time.Now()

		if !exists {
			l.ips[ip] = &ipState{
				windowStart: now,
				requests:    1,
				lastSeen:    now,
			}
			l.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		state.lastSeen = now

		// Si el tiempo transcurrido desde el inicio de la ventana supera el límite, resetear la ventana
		if now.Sub(state.windowStart) > l.window {
			state.windowStart = now
			state.requests = 1
			l.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		// Si supera la tasa permitida en la ventana actual
		if state.requests >= l.rate {
			l.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error": "Límite de peticiones excedido. Por favor, intente más tarde."}`))
			return
		}

		state.requests++
		l.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// cleanupLoop elimina las IPs inactivas periódicamente para evitar fugas de memoria
func (l *ipLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		for ip, state := range l.ips {
			// Si ha estado inactivo por el doble del tiempo de la ventana, eliminarlo de memoria
			if now.Sub(state.lastSeen) > l.window*2 {
				delete(l.ips, ip)
			}
		}
		l.mu.Unlock()
	}
}
