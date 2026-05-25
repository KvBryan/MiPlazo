package goals

import (
    "database/sql"
    "encoding/json"
    "net/http"
    "strconv"
    "time"

    "miplazo/internal/security"

    "github.com/go-chi/chi/v5"
)

type Goal struct {
    ID            int       `json:"id"`
    UserID        int       `json:"user_id"`
    Title         string    `json:"title"`
    TargetAmount  float64   `json:"target_amount"`
    CurrentAmount float64   `json:"current_amount"`
    Deadline      time.Time `json:"deadline"`
    CreatedAt     time.Time `json:"created_at"`
}

type CreateGoalRequest struct {
    Title        string  `json:"title"`
    TargetAmount float64 `json:"target_amount"`
    Deadline     string  `json:"deadline"` 
}

type UpdateProgressRequest struct {
    CurrentAmount float64 `json:"current_amount"`
}

type GoalResponse struct {
    ID                    int       `json:"id"`
    Title                 string    `json:"title"`
    TargetAmount          float64   `json:"target_amount"`
    CurrentAmount         float64   `json:"current_amount"`
    Deadline              time.Time `json:"deadline"`
    MonthsRemaining       float64   `json:"months_remaining"`
    WeeksRemaining        float64   `json:"weeks_remaining"`
    MonthlySavingRequired float64   `json:"monthly_saving_required"`
    WeeklySavingRequired  float64   `json:"weekly_saving_required"`
    ProgressPercentage    float64   `json:"progress_percentage"`
}

type Handler struct {
    db *sql.DB
}

func NewHandler(db *sql.DB) *Handler {
    return &Handler{db: db}
}

func (h *Handler) CreateGoal(w http.ResponseWriter, r *http.Request) {
    userID, ok := security.GetUserID(r.Context())
    if !ok {
        h.respondWithError(w, http.StatusUnauthorized, "Usuario no autenticado")
        return
    }

    // 🔥 PARCHE DE SEGURIDAD: Limitar body a 1MB para mitigar ataques DoS por agotamiento de RAM
    r.Body = http.MaxBytesReader(w, r.Body, 1048576)

    var req CreateGoalRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, "Cuerpo JSON inválido")
        return
    }

    if req.Title == "" || req.TargetAmount <= 0 {
        h.respondWithError(w, http.StatusBadRequest, "El título es obligatorio y el monto objetivo debe ser mayor a 0")
        return
    }

    deadline, err := time.Parse("2006-01-02", req.Deadline)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, "Formato de fecha límite inválido, use AAAA-MM-DD")
        return
    }

    if deadline.Before(time.Now()) {
        h.respondWithError(w, http.StatusBadRequest, "La fecha límite debe ser en el futuro")
        return
    }

    query := `
        INSERT INTO saving_goals (user_id, title, target_amount, current_amount, deadline, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, current_amount, created_at
    `
    var goal Goal
    err = h.db.QueryRowContext(
        r.Context(), query, userID, req.Title, req.TargetAmount, 0.0, deadline, time.Now(),
    ).Scan(&goal.ID, &goal.CurrentAmount, &goal.CreatedAt)

    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, "No se pudo guardar la meta de ahorro")
        return
    }

    goal.UserID = userID
    goal.Title = req.Title
    goal.TargetAmount = req.TargetAmount
    goal.Deadline = deadline

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    _ = json.NewEncoder(w).Encode(goal)
}

func (h *Handler) GetGoals(w http.ResponseWriter, r *http.Request) {
    userID, ok := security.GetUserID(r.Context())
    if !ok {
        h.respondWithError(w, http.StatusUnauthorized, "Usuario no autenticado")
        return
    }

    query := `
        SELECT id, title, target_amount, current_amount, deadline
        FROM saving_goals
        WHERE user_id = $1
        ORDER BY created_at DESC
    `
    rows, err := h.db.QueryContext(r.Context(), query, userID)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, "Error al consultar las metas de ahorro")
        return
    }
    defer rows.Close()

    goalsList := []GoalResponse{}
    now := time.Now()

    for rows.Next() {
        var g Goal
        if err := rows.Scan(&g.ID, &g.Title, &g.TargetAmount, &g.CurrentAmount, &g.Deadline); err != nil {
            h.respondWithError(w, http.StatusInternalServerError, "Error al procesar las metas de ahorro")
            return
        }

        duration := g.Deadline.Sub(now)
        daysRemaining := duration.Hours() / 24
        weeksRemaining := daysRemaining / 7
        if weeksRemaining < 0 {
            weeksRemaining = 0
        }

        yearsDiff := g.Deadline.Year() - now.Year()
        monthsDiff := int(g.Deadline.Month()) - int(now.Month())
        monthsRemaining := float64(yearsDiff*12 + monthsDiff)
        if monthsRemaining < 0 {
            monthsRemaining = 0
        }

        remainingAmount := g.TargetAmount - g.CurrentAmount
        if remainingAmount < 0 {
            remainingAmount = 0
        }

        var monthlySavingRequired float64
        if monthsRemaining > 0 {
            monthlySavingRequired = remainingAmount / monthsRemaining
        } else {
            monthlySavingRequired = remainingAmount
        }

        var weeklySavingRequired float64
        if weeksRemaining > 0 {
            weeklySavingRequired = remainingAmount / weeksRemaining
        } else {
            weeklySavingRequired = remainingAmount
        }

        progressPercentage := (g.CurrentAmount / g.TargetAmount) * 100
        if progressPercentage > 100 {
            progressPercentage = 100
        }

        goalsList = append(goalsList, GoalResponse{
            ID:                    g.ID,
            Title:                 g.Title,
            TargetAmount:          g.TargetAmount,
            CurrentAmount:         g.CurrentAmount,
            Deadline:              g.Deadline,
            MonthsRemaining:       monthsRemaining,
            WeeksRemaining:        weeksRemaining,
            MonthlySavingRequired: monthlySavingRequired,
            WeeklySavingRequired:  weeklySavingRequired,
            ProgressPercentage:    progressPercentage,
        })
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    _ = json.NewEncoder(w).Encode(goalsList)
}

func (h *Handler) UpdateProgress(w http.ResponseWriter, r *http.Request) {
    userID, ok := security.GetUserID(r.Context())
    if !ok {
        h.respondWithError(w, http.StatusUnauthorized, "Usuario no autenticado")
        return
    }

    goalIDStr := chi.URLParam(r, "id")
    goalID, err := strconv.Atoi(goalIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, "ID de meta inválido")
        return
    }

    // 🔥 PARCHE DE SEGURIDAD: Limitar body a 1MB para mitigar ataques DoS
    r.Body = http.MaxBytesReader(w, r.Body, 1048576)

    var req UpdateProgressRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.respondWithError(w, http.StatusBadRequest, "Cuerpo JSON inválido")
        return
    }

    if req.CurrentAmount < 0 {
        h.respondWithError(w, http.StatusBadRequest, "El monto actual no puede ser menor a 0")
        return
    }

	// 1. Calcular el balance neto de transacciones (ingresos - gastos)
	var netBalance float64
	balanceQuery := `
		SELECT COALESCE(SUM(CASE WHEN type = 'INCOME' THEN amount ELSE -amount END), 0)
		FROM transactions
		WHERE user_id = $1
	`
	err = h.db.QueryRowContext(r.Context(), balanceQuery, userID).Scan(&netBalance)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Error al verificar el balance financiero")
		return
	}

	// 2. Calcular la suma de dinero ya retenido en OTRAS metas de ahorro
	var otherGoalsAllocated float64
	allocatedQuery := `
		SELECT COALESCE(SUM(current_amount), 0)
		FROM saving_goals
		WHERE user_id = $1 AND id != $2
	`
	err = h.db.QueryRowContext(r.Context(), allocatedQuery, userID, goalID).Scan(&otherGoalsAllocated)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Error al verificar montos asignados en otras metas")
		return
	}

	// 3. Validar consistencia financiera (Monto solicitado + Monto en otras metas <= Balance General Neto)
	if req.CurrentAmount+otherGoalsAllocated > netBalance {
		h.respondWithError(w, http.StatusBadRequest, "Saldo insuficiente en tu balance general para cubrir este monto de ahorro")
		return
	}

	query := `
		UPDATE saving_goals
		SET current_amount = $1
		WHERE id = $2 AND user_id = $3
	`
	result, err := h.db.ExecContext(r.Context(), query, req.CurrentAmount, goalID, userID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "No se pudo actualizar el progreso de la meta")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		h.respondWithError(w, http.StatusNotFound, "Meta de ahorro no encontrada o no pertenece al usuario")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"message":        "Progreso de la meta actualizado correctamente",
		"current_amount": req.CurrentAmount,
	})
}

func (h *Handler) DeleteGoal(w http.ResponseWriter, r *http.Request) {
    userID, ok := security.GetUserID(r.Context())
    if !ok {
        h.respondWithError(w, http.StatusUnauthorized, "Usuario no autenticado")
        return
    }

    goalIDStr := chi.URLParam(r, "id")
    goalID, err := strconv.Atoi(goalIDStr)
    if err != nil {
        h.respondWithError(w, http.StatusBadRequest, "ID de meta inválido")
        return
    }

    query := `DELETE FROM saving_goals WHERE id = $1 AND user_id = $2`
    result, err := h.db.ExecContext(r.Context(), query, goalID, userID)
    if err != nil {
        h.respondWithError(w, http.StatusInternalServerError, "No se pudo eliminar la meta de ahorro")
        return
    }

    rowsAffected, err := result.RowsAffected()
    if err != nil || rowsAffected == 0 {
        h.respondWithError(w, http.StatusNotFound, "Meta de ahorro no encontrada o no pertenece al usuario")
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    _ = json.NewEncoder(w).Encode(map[string]string{"message": "Meta de ahorro eliminada con éxito"})
}

func (h *Handler) respondWithError(w http.ResponseWriter, statusCode int, message string) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    _ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}