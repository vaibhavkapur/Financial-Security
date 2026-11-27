package policy

import (
	"fmt"
	"strings"
	"sync"

	"github.com/financial-security/financial-api-security-gateway/src/domain"
)

// Engine evaluates per-resource deny-by-default authorization rules.
type Engine struct {
	mu       sync.RWMutex
	policies domain.PolicySet
	clients  map[string]domain.ClientIdentity
}

func NewEngine(ps domain.PolicySet, reg domain.ClientRegistry) (*Engine, error) {
	if err := domain.ValidatePolicySet(ps); err != nil {
		return nil, err
	}
	if err := domain.ValidateClientRegistry(reg); err != nil {
		return nil, err
	}
	clientMap := make(map[string]domain.ClientIdentity, len(reg.Clients))
	for _, c := range reg.Clients {
		clientMap[c.ClientID] = c
	}
	return &Engine{
		policies: ps,
		clients:  clientMap,
	}, nil
}

// LookupClient retrieves a registered mock client identity.
func (e *Engine) LookupClient(clientID string) (domain.ClientIdentity, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	c, ok := e.clients[clientID]
	return c, ok
}

// RevokeClient marks a client identity as revoked at runtime.
func (e *Engine) RevokeClient(clientID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.clients[clientID]
	if !ok {
		return fmt.Errorf("unknown client %q", clientID)
	}
	c.Status = "revoked"
	e.clients[clientID] = c
	return nil
}

// MatchRule finds the first matching policy rule for an HTTP method and path.
// Returns nil when no rule matches (triggering deny-by-default).
func (e *Engine) MatchRule(method, path string) *domain.PolicyRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	normMethod := strings.ToUpper(strings.TrimSpace(method))
	for i := range e.policies.Rules {
		r := &e.policies.Rules[i]
		if strings.ToUpper(r.Method) == normMethod && matchPathPattern(r.PathPattern, path) {
			cp := *r
			return &cp
		}
	}
	return nil
}

// Authorize checks client role, token scopes, and client-registered scope ceilings against the matched rule.
func (e *Engine) Authorize(client domain.ClientIdentity, claims domain.TokenClaims, rule *domain.PolicyRule) (domain.ReasonCode, string) {
	if rule == nil {
		return domain.ReasonPolicyDefaultDeny, "request denied by default: no matching authorization policy"
	}
	if client.Status != "active" {
		return domain.ReasonClientRevoked, fmt.Sprintf("client %q status is %q", client.ClientID, client.Status)
	}

	roleAllowed := false
	for _, r := range rule.AllowedRoles {
		if r == client.Role {
			roleAllowed = true
			break
		}
	}
	if !roleAllowed {
		return domain.ReasonRoleForbidden, fmt.Sprintf("role %q is not authorized for policy %q", client.Role, rule.ID)
	}

	tokenScopes := make(map[string]bool, len(claims.Scopes))
	for _, s := range claims.Scopes {
		tokenScopes[s] = true
	}
	clientScopes := make(map[string]bool, len(client.AllowedScopes))
	for _, s := range client.AllowedScopes {
		clientScopes[s] = true
	}

	for _, reqScope := range rule.RequiredScopes {
		if !tokenScopes[reqScope] {
			return domain.ReasonScopeInsufficient, fmt.Sprintf("missing required scope %q", reqScope)
		}
		if !clientScopes[reqScope] {
			return domain.ReasonScopeNotGrantedToActor, fmt.Sprintf("scope %q is not granted to client %q", reqScope, client.ClientID)
		}
	}

	return domain.ReasonAllowed, "authorized"
}

// matchPathPattern matches exact paths or single-segment templates like /v1/accounts/{account_id}/balance.
func matchPathPattern(pattern, path string) bool {
	if pattern == path {
		return true
	}
	pSegs := splitPath(pattern)
	aSegs := splitPath(path)
	if len(pSegs) != len(aSegs) {
		return false
	}
	for i := range pSegs {
		ps := pSegs[i]
		as := aSegs[i]
		if strings.HasPrefix(ps, "{") && strings.HasSuffix(ps, "}") && len(ps) > 2 {
			if as == "" || strings.Contains(as, "..") {
				return false
			}
			continue
		}
		if ps != as {
			return false
		}
	}
	return true
}

func splitPath(p string) []string {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}
