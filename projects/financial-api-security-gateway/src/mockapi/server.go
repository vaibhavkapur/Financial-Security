package mockapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// OrderRequest is a synthetic paper-trading order payload.
type OrderRequest struct {
	AccountID  string  `json:"account_id"`
	Symbol     string  `json:"symbol"`
	Side       string  `json:"side"`
	Qty        int     `json:"qty"`
	LimitPrice float64 `json:"limit_price"`
}

// SimulatedFinancialAPI serves synthetic, offline mock financial endpoints.
type SimulatedFinancialAPI struct {
	mu       sync.RWMutex
	balances map[string]float64
	orders   map[string]map[string]any
	orderSeq atomic.Uint64
}

func NewSimulatedFinancialAPI() *SimulatedFinancialAPI {
	return &SimulatedFinancialAPI{
		balances: map[string]float64{
			"ACC-1001": 125000.50,
			"ACC-2002": 500000.00,
		},
		orders: make(map[string]map[string]any),
	}
}

func (api *SimulatedFinancialAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/accounts/", api.handleAccounts)
	mux.HandleFunc("/v1/orders", api.handleOrders)
	mux.HandleFunc("/v1/orders/", api.handleOrderByID)
	mux.HandleFunc("/v1/audit/export", api.handleAuditExport)
	mux.HandleFunc("/v1/slow", api.handleSlow)
	return mux
}

func (api *SimulatedFinancialAPI) handleAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/balance") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/v1/accounts/")
	accountID := strings.TrimSuffix(trimmed, "/balance")
	api.mu.RLock()
	bal, ok := api.balances[accountID]
	api.mu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error":      "synthetic_account_not_found",
			"account_id": accountID,
		})
		return
	}
	currency := r.URL.Query().Get("currency")
	if currency == "" {
		currency = "USD"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":            "SIMULATED_PAPER_ONLY",
		"account_id":      accountID,
		"currency":        currency,
		"balance":         bal,
		"verified_client": r.Header.Get("X-Gateway-Verified-Client"),
		"request_id":      r.Header.Get("X-Request-ID"),
	})
}

func (api *SimulatedFinancialAPI) handleOrders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req OrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid order json"})
		return
	}
	if req.AccountID == "" || req.Symbol == "" || req.Qty <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "account_id, symbol, and qty > 0 required"})
		return
	}
	orderID := fmt.Sprintf("SIM-ORD-%05d", api.orderSeq.Add(1))
	record := map[string]any{
		"mode":            "SIMULATED_PAPER_ONLY",
		"order_id":        orderID,
		"status":          "ACCEPTED_PAPER",
		"account_id":      req.AccountID,
		"symbol":          req.Symbol,
		"side":            req.Side,
		"qty":             req.Qty,
		"limit_price":     req.LimitPrice,
		"verified_client": r.Header.Get("X-Gateway-Verified-Client"),
		"request_id":      r.Header.Get("X-Request-ID"),
	}
	api.mu.Lock()
	api.orders[orderID] = record
	api.mu.Unlock()
	writeJSON(w, http.StatusOK, record)
}

func (api *SimulatedFinancialAPI) handleOrderByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	orderID := strings.TrimPrefix(r.URL.Path, "/v1/orders/")
	api.mu.RLock()
	rec, ok := api.orders[orderID]
	api.mu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "order_not_found", "order_id": orderID})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (api *SimulatedFinancialAPI) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	api.mu.RLock()
	orderCount := len(api.orders)
	api.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":                 "SIMULATED_PAPER_ONLY",
		"synthetic_order_rows": orderCount,
		"verified_client":      r.Header.Get("X-Gateway-Verified-Client"),
		"verified_role":        r.Header.Get("X-Gateway-Verified-Role"),
	})
}

func (api *SimulatedFinancialAPI) handleSlow(w http.ResponseWriter, r *http.Request) {
	delayMs := 750
	if q := r.URL.Query().Get("delay_ms"); q != "" {
		if parsed, err := strconv.Atoi(q); err == nil && parsed >= 0 && parsed <= 10000 {
			delayMs = parsed
		}
	}
	select {
	case <-time.After(time.Duration(delayMs) * time.Millisecond):
		writeJSON(w, http.StatusOK, map[string]any{
			"mode":     "SIMULATED_PAPER_ONLY",
			"delayed":  delayMs,
			"status":   "COMPLETED_AFTER_DELAY",
			"req_id":   r.Header.Get("X-Request-ID"),
		})
	case <-r.Context().Done():
		return
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
