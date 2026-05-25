package transactions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"miplazo/internal/security"

	"github.com/go-chi/chi/v5"
	"github.com/microcosm-cc/bluemonday"
)

// Transaction representa el modelo de una transacción en la base de datos.
type Transaction struct {
	ID              int       `json:"id"`
	UserID          int       `json:"user_id"`
	Type            string    `json:"type"` // 'INCOME' o 'EXPENSE'
	Amount          float64   `json:"amount"`
	Description     string    `json:"description"`
	TransactionDate time.Time `json:"transaction_date"`
	CreatedAt       time.Time `json:"created_at"`
}

// TransactionRequest define los campos permitidos para la creación/actualización de transacciones.
type TransactionRequest struct {
	Type            string  `json:"type"`
	Amount          float64 `json:"amount"`
	Description     string  `json:"description"`
	TransactionDate string  `json:"transaction_date"` // Formato esperado: "AAAA-MM-DD"
}

// Handler contiene las dependencias del módulo de transacciones.
type Handler struct {
	db *sql.DB
}

// NewHandler inicializa el manejador de transacciones.
func NewHandler(db *sql.DB) *Handler {
	return &Handler{db: db}
}

// CreateTransaction registra una nueva transacción (ingreso o gasto) para el usuario.
func (h *Handler) CreateTransaction(w http.ResponseWriter, r *http.Request) {
	userID, ok := security.GetUserID(r.Context())
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "Usuario no autenticado")
		return
	}

	// Mitigación DoS: Limitar el cuerpo a 1MB
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var req TransactionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Cuerpo JSON inválido")
		return
	}

	// Validaciones de negocio y seguridad
	if req.Type != "INCOME" && req.Type != "EXPENSE" {
		h.respondWithError(w, http.StatusBadRequest, "El tipo debe ser estrictamente 'INCOME' o 'EXPENSE'")
		return
	}
	if req.Amount <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "El monto debe ser mayor a 0")
		return
	}

	txDate, err := time.Parse("2006-01-02", req.TransactionDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Formato de fecha de transacción inválido, use AAAA-MM-DD")
		return
	}

	// Sanitización estricta de la descripción para evitar XSS Almacenado (OWASP compliance)
	sanitizedDescription := bluemonday.StrictPolicy().Sanitize(req.Description)

	// Consulta parametrizada (prevención de SQL Injection)
	query := `
		INSERT INTO transactions (user_id, type, amount, description, transaction_date, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at
	`
	var t Transaction
	err = h.db.QueryRowContext(
		r.Context(), query, userID, req.Type, req.Amount, sanitizedDescription, txDate, time.Now(),
	).Scan(&t.ID, &t.CreatedAt)

	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "No se pudo registrar la transacción")
		return
	}

	t.UserID = userID
	t.Type = req.Type
	t.Amount = req.Amount
	t.Description = sanitizedDescription
	t.TransactionDate = txDate

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(t)
}

// GetTransactions obtiene todas las transacciones del usuario ordenadas de forma descendente.
func (h *Handler) GetTransactions(w http.ResponseWriter, r *http.Request) {
	userID, ok := security.GetUserID(r.Context())
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "Usuario no autenticado")
		return
	}

	// Consulta parametrizada con orden descendente por fecha (estilo historial contable)
	query := `
		SELECT id, type, amount, description, transaction_date, created_at
		FROM transactions
		WHERE user_id = $1 AND is_active = TRUE
		ORDER BY transaction_date DESC, created_at DESC
	`
	rows, err := h.db.QueryContext(r.Context(), query, userID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Error al consultar las transacciones")
		return
	}
	defer rows.Close() // Evita fugas de memoria y descriptores de conexión en baja RAM

	txs := []Transaction{}
	for rows.Next() {
		var t Transaction
		err := rows.Scan(&t.ID, &t.Type, &t.Amount, &t.Description, &t.TransactionDate, &t.CreatedAt)
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, "Error al procesar las transacciones")
			return
		}
		t.UserID = userID
		txs = append(txs, t)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(txs)
}

// UpdateTransaction actualiza los campos de una transacción existente mitigando IDOR.
func (h *Handler) UpdateTransaction(w http.ResponseWriter, r *http.Request) {
	userID, ok := security.GetUserID(r.Context())
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "Usuario no autenticado")
		return
	}

	txIDStr := chi.URLParam(r, "id")
	txID, err := strconv.Atoi(txIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "ID de transacción inválido")
		return
	}

	// Mitigación DoS
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var req TransactionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Cuerpo JSON inválido")
		return
	}

	if req.Type != "INCOME" && req.Type != "EXPENSE" {
		h.respondWithError(w, http.StatusBadRequest, "El tipo debe ser estrictamente 'INCOME' o 'EXPENSE'")
		return
	}
	if req.Amount <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "El monto debe ser mayor a 0")
		return
	}

	txDate, err := time.Parse("2006-01-02", req.TransactionDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Formato de fecha de transacción inválido, use AAAA-MM-DD")
		return
	}

	// Sanitización estricta de la descripción para evitar XSS Almacenado (OWASP compliance)
	sanitizedDescription := bluemonday.StrictPolicy().Sanitize(req.Description)

	// Iniciar transacción de base de datos para asegurar consistencia contable
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Error interno de base de datos")
		return
	}
	defer tx.Rollback()

	// 1. Obtener tipo y monto de la transacción y bloquear fila para evitar condiciones de carrera (IDOR Check)
	var txType string
	var txAmount float64
	selectQuery := `SELECT type, amount FROM transactions WHERE id = $1 AND user_id = $2 AND is_active = TRUE FOR UPDATE`
	err = tx.QueryRowContext(r.Context(), selectQuery, txID, userID).Scan(&txType, &txAmount)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.respondWithError(w, http.StatusNotFound, "Transacción no encontrada o no pertenece al usuario")
		} else {
			h.respondWithError(w, http.StatusInternalServerError, "Error al verificar la transacción")
		}
		return
	}

	// 2. Actualizar la transacción
	updateQuery := `
		UPDATE transactions
		SET type = $1, amount = $2, description = $3, transaction_date = $4
		WHERE id = $5 AND user_id = $6 AND is_active = TRUE
	`
	_, err = tx.ExecContext(r.Context(), updateQuery, req.Type, req.Amount, sanitizedDescription, txDate, txID, userID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "No se pudo actualizar la transacción")
		return
	}

	// 3. Calcular el nuevo balance general neto del usuario (excluyendo transacciones borradas lógicamente)
	var newNetBalance float64
	balanceQuery := `
		SELECT COALESCE(SUM(CASE WHEN type = 'INCOME' THEN amount ELSE -amount END), 0)
		FROM transactions
		WHERE user_id = $1 AND is_active = TRUE
	`
	err = tx.QueryRowContext(r.Context(), balanceQuery, userID).Scan(&newNetBalance)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Error al recalcular el balance financiero")
		return
	}

	// 4. Ajustar metas a la baja progresivamente si el total asignado supera el nuevo balance general neto disponible
	if err := h.adjustGoalsToBalance(r.Context(), tx, userID, newNetBalance); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Error al ajustar el saldo de las metas")
		return
	}

	// Confirmar transacción
	if err := tx.Commit(); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Error al confirmar los cambios en la base de datos")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Transacción actualizada correctamente",
		"id":      txID,
	})
}

// DeleteTransaction elimina una transacción mitigando IDOR y manteniendo consistencia con las metas de ahorro.
func (h *Handler) DeleteTransaction(w http.ResponseWriter, r *http.Request) {
	userID, ok := security.GetUserID(r.Context())
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "Usuario no autenticado")
		return
	}

	txIDStr := chi.URLParam(r, "id")
	txID, err := strconv.Atoi(txIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "ID de transacción inválido")
		return
	}

	// Iniciar transacción de base de datos para asegurar consistencia contable
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Error interno de base de datos")
		return
	}
	defer tx.Rollback()

	// 1. Obtener tipo y monto de la transacción y bloquear fila para evitar condiciones de carrera (IDOR Check)
	var txType string
	var txAmount float64
	selectQuery := `SELECT type, amount FROM transactions WHERE id = $1 AND user_id = $2 AND is_active = TRUE FOR UPDATE`
	err = tx.QueryRowContext(r.Context(), selectQuery, txID, userID).Scan(&txType, &txAmount)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.respondWithError(w, http.StatusNotFound, "Transacción no encontrada o no pertenece al usuario")
		} else {
			h.respondWithError(w, http.StatusInternalServerError, "Error al verificar la transacción")
		}
		return
	}

	// 2. Eliminar la transacción lógicamente (Soft Delete)
	deleteQuery := `UPDATE transactions SET is_active = FALSE WHERE id = $1 AND user_id = $2 AND is_active = TRUE`
	_, err = tx.ExecContext(r.Context(), deleteQuery, txID, userID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "No se pudo eliminar la transacción")
		return
	}

	// 3. Calcular el nuevo balance general neto del usuario (excluyendo transacciones borradas lógicamente)
	var newNetBalance float64
	balanceQuery := `
		SELECT COALESCE(SUM(CASE WHEN type = 'INCOME' THEN amount ELSE -amount END), 0)
		FROM transactions
		WHERE user_id = $1 AND is_active = TRUE
	`
	err = tx.QueryRowContext(r.Context(), balanceQuery, userID).Scan(&newNetBalance)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Error al recalcular el balance financiero")
		return
	}

	// 4. Ajustar metas a la baja progresivamente si el total asignado supera el nuevo balance general neto disponible
	if err := h.adjustGoalsToBalance(r.Context(), tx, userID, newNetBalance); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Error al ajustar el saldo de las metas")
		return
	}

	// Confirmar transacción de forma segura
	if err := tx.Commit(); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Error al confirmar los cambios en la base de datos")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Transacción eliminada con éxito"})
}

// adjustGoalsToBalance reduce progresivamente el saldo asignado en las metas de ahorro si supera el balance general neto.
func (h *Handler) adjustGoalsToBalance(ctx context.Context, tx *sql.Tx, userID int, newNetBalance float64) error {
	var totalAllocated float64
	allocatedQuery := `
		SELECT COALESCE(SUM(current_amount), 0)
		FROM saving_goals
		WHERE user_id = $1 AND is_active = TRUE
	`
	err := tx.QueryRowContext(ctx, allocatedQuery, userID).Scan(&totalAllocated)
	if err != nil {
		return err
	}

	if totalAllocated > newNetBalance {
		excess := totalAllocated - newNetBalance

		goalsQuery := `
			SELECT id, current_amount
			FROM saving_goals
			WHERE user_id = $1 AND current_amount > 0 AND is_active = TRUE
			ORDER BY created_at DESC
			FOR UPDATE
		`
		rows, err := tx.QueryContext(ctx, goalsQuery, userID)
		if err != nil {
			return err
		}
		defer rows.Close()

		type GoalAllocation struct {
			ID            int
			CurrentAmount float64
		}
		var allocations []GoalAllocation
		for rows.Next() {
			var ga GoalAllocation
			if err := rows.Scan(&ga.ID, &ga.CurrentAmount); err != nil {
				return err
			}
			allocations = append(allocations, ga)
		}
		rows.Close()

		for _, ga := range allocations {
			if excess <= 0 {
				break
			}

			var newAmount float64
			if ga.CurrentAmount >= excess {
				newAmount = ga.CurrentAmount - excess
				excess = 0
			} else {
				newAmount = 0
				excess -= ga.CurrentAmount
			}

			updateGoalQuery := `UPDATE saving_goals SET current_amount = $1 WHERE id = $2 AND is_active = TRUE`
			_, err = tx.ExecContext(ctx, updateGoalQuery, newAmount, ga.ID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// respondWithError responde de forma consistente con formato JSON de error.
func (h *Handler) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
