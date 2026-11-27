package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/financial-security/digital-asset-custody-platform/src/pkg/domain"
)

// Engine enforces deny-by-default custody authorization rules.
// It is pure and side-effect-free; callers pass current daily spend and clock time.
type Engine struct {
	cfg            domain.PolicyConfig
	policyDigest   string
	allowedNets    map[string]bool
	approverMap    map[string]domain.ActorConfig
	requesterMap   map[string]domain.ActorConfig
}

// LoadConfig reads and strictly validates a versioned JSON policy configuration file.
func LoadConfig(path string) (domain.PolicyConfig, error) {
	if strings.TrimSpace(path) == "" {
		return domain.PolicyConfig{}, domain.NewError(domain.ErrMissingConfig, "policy config path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return domain.PolicyConfig{}, domain.WrapError(domain.ErrMissingConfig, "policy config file not found: "+path, err)
		}
		return domain.PolicyConfig{}, domain.WrapError(domain.ErrInvalidConfig, "unable to read policy config file", err)
	}
	var cfg domain.PolicyConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return domain.PolicyConfig{}, domain.WrapError(domain.ErrInvalidConfig, "invalid policy config JSON", err)
	}
	if err := ValidateConfig(cfg); err != nil {
		return domain.PolicyConfig{}, err
	}
	return cfg, nil
}

// ValidateConfig checks structural and safety invariants on PolicyConfig.
// Explicitly rejects mainnet or production configurations.
func ValidateConfig(cfg domain.PolicyConfig) error {
	if cfg.SchemaVersion != domain.CurrentSchemaVersion {
		return domain.NewError(domain.ErrInvalidConfig, "unsupported policy schema_version")
	}
	if strings.TrimSpace(cfg.PolicyVersion) == "" {
		return domain.NewError(domain.ErrInvalidConfig, "policy_version is required")
	}
	if strings.Contains(strings.ToLower(cfg.Environment), "prod") || strings.Contains(strings.ToLower(cfg.Environment), "mainnet") {
		return domain.NewError(domain.ErrInvalidConfig, "production or mainnet environments are prohibited in prototype custody")
	}
	if len(cfg.AllowedNetworks) == 0 {
		return domain.NewError(domain.ErrInvalidConfig, "at least one mock/testnet allowed_network is required")
	}
	for _, net := range cfg.AllowedNetworks {
		if !isSafeMockOrTestnet(net) {
			return domain.NewError(domain.ErrUnsupportedNetwork, "forbidden network in policy config (mock/testnet only): "+net)
		}
	}
	if cfg.ConfirmationDepth < 1 {
		return domain.NewError(domain.ErrInvalidConfig, "confirmation_depth must be >= 1")
	}
	if len(cfg.Vaults) == 0 {
		return domain.NewError(domain.ErrInvalidConfig, "at least one vault must be configured")
	}
	if len(cfg.Approvers) == 0 {
		return domain.NewError(domain.ErrInvalidConfig, "at least one approver must be configured")
	}
	for vaultID, vp := range cfg.Vaults {
		if vp.VaultID != vaultID {
			return domain.NewError(domain.ErrInvalidConfig, "vault_id mismatch for key "+vaultID)
		}
		if !isSafeMockOrTestnet(vp.Network) {
			return domain.NewError(domain.ErrUnsupportedNetwork, "vault configured with forbidden network: "+vp.Network)
		}
		if !domain.ValidateAddress(vp.SourceAddress) {
			return domain.NewError(domain.ErrInvalidConfig, "vault source_address is invalid for "+vaultID)
		}
		if vp.SigningThreshold < 1 || vp.SigningThreshold > len(vp.SignerIDs) {
			return domain.NewError(domain.ErrInvalidConfig, "invalid signing_threshold for vault "+vaultID)
		}
		if len(vp.Assets) == 0 {
			return domain.NewError(domain.ErrInvalidConfig, "vault must define at least one supported asset: "+vaultID)
		}
		for assetName, ap := range vp.Assets {
			if ap.MaxSingleTransfer <= 0 || ap.DailyLimit <= 0 || ap.MaxSingleTransfer > ap.DailyLimit {
				return domain.NewError(domain.ErrInvalidConfig, fmt.Sprintf("invalid amount limits for %s/%s", vaultID, assetName))
			}
			if ap.StandardApprovalQuorum < 1 || ap.HighValueApprovalQuorum < ap.StandardApprovalQuorum {
				return domain.NewError(domain.ErrInvalidConfig, fmt.Sprintf("invalid approval quorum for %s/%s", vaultID, assetName))
			}
		}
		for _, dest := range vp.DestinationAllowlist {
			if !domain.ValidateAddress(dest.Address) {
				return domain.NewError(domain.ErrInvalidConfig, "invalid allowlist destination address in vault "+vaultID)
			}
			if dest.MaxSingleTransfer <= 0 {
				return domain.NewError(domain.ErrInvalidConfig, "allowlist destination max_single_transfer must be > 0")
			}
		}
	}
	return nil
}

func isSafeMockOrTestnet(network string) bool {
	n := strings.ToLower(strings.TrimSpace(network))
	if n == "" || strings.Contains(n, "mainnet") || strings.Contains(n, "production") {
		return false
	}
	return strings.HasPrefix(n, "mock-") || strings.HasSuffix(n, "-testnet") || strings.HasSuffix(n, "-sepolia")
}

// NewEngine constructs a validated, immutable policy Engine.
func NewEngine(cfg domain.PolicyConfig) (*Engine, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, domain.WrapError(domain.ErrInvalidConfig, "failed to hash policy config", err)
	}
	sum := sha256.Sum256(raw)

	allowedNets := make(map[string]bool, len(cfg.AllowedNetworks))
	for _, n := range cfg.AllowedNetworks {
		allowedNets[strings.ToLower(strings.TrimSpace(n))] = true
	}
	approverMap := make(map[string]domain.ActorConfig, len(cfg.Approvers))
	for _, a := range cfg.Approvers {
		approverMap[a.ID] = a
	}
	requesterMap := make(map[string]domain.ActorConfig, len(cfg.Requesters))
	for _, r := range cfg.Requesters {
		requesterMap[r.ID] = r
	}

	return &Engine{
		cfg:          cfg,
		policyDigest: hex.EncodeToString(sum[:]),
		allowedNets:  allowedNets,
		approverMap:  approverMap,
		requesterMap: requesterMap,
	}, nil
}

func (e *Engine) Config() domain.PolicyConfig { return e.cfg }
func (e *Engine) PolicyDigest() string        { return e.policyDigest }

// Evaluate applies deny-by-default rules to a TransferIntent.
// Returns both the PolicyDecision (recording ALLOW/DENY) and a typed CustodyError if denied.
func (e *Engine) Evaluate(intent domain.TransferIntent, dailySpent int64, now time.Time) (domain.PolicyDecision, error) {
	norm := intent
	norm.Normalize()

	decision := domain.PolicyDecision{
		Allowed:       false,
		PolicyVersion: e.cfg.PolicyVersion,
		PolicyDigest:  e.policyDigest,
		EvaluatedAt:   now.UTC().Format(time.RFC3339),
	}

	deny := func(code domain.ErrorCode, reason string) (domain.PolicyDecision, error) {
		decision.Allowed = false
		decision.ReasonCode = code
		decision.Reason = reason
		return decision, domain.NewError(code, reason)
	}

	if err := norm.ValidateBasic(now); err != nil {
		code := domain.CodeOf(err)
		if code == "" {
			code = domain.ErrInvalidSchema
		}
		return deny(code, err.Error())
	}

	if !isSafeMockOrTestnet(norm.Network) || !e.allowedNets[norm.Network] {
		return deny(domain.ErrUnsupportedNetwork, "network is not permitted by custody policy: "+norm.Network)
	}

	reqActor, ok := e.requesterMap[norm.RequestedBy]
	if !ok || !reqActor.Active {
		return deny(domain.ErrUnauthorizedRequester, "requester is not authorized or inactive: "+norm.RequestedBy)
	}

	vault, ok := e.cfg.Vaults[norm.VaultID]
	if !ok {
		return deny(domain.ErrUnknownVault, "unknown vault_id: "+norm.VaultID)
	}
	if !vault.Active {
		return deny(domain.ErrVaultInactive, "vault is inactive: "+norm.VaultID)
	}
	if !strings.EqualFold(vault.Network, norm.Network) {
		return deny(domain.ErrUnsupportedNetwork, "intent network does not match vault network")
	}
	if !strings.EqualFold(vault.SourceAddress, norm.SourceAddress) {
		return deny(domain.ErrInvalidAddress, "source_address does not match configured vault source_address")
	}

	assetPolicy, ok := vault.Assets[norm.Asset]
	if !ok {
		return deny(domain.ErrUnsupportedAsset, "asset is not supported for vault: "+norm.Asset)
	}
	if !strings.EqualFold(assetPolicy.Unit, norm.Unit) {
		return deny(domain.ErrUnsupportedAsset, fmt.Sprintf("unit mismatch for %s: got %s, expected %s", norm.Asset, norm.Unit, assetPolicy.Unit))
	}

	// Destination allowlist (deny-by-default).
	var matchedDest *domain.AllowlistedDestination
	for i := range vault.DestinationAllowlist {
		if strings.EqualFold(vault.DestinationAllowlist[i].Address, norm.DestinationAddress) {
			matchedDest = &vault.DestinationAllowlist[i]
			break
		}
	}
	if matchedDest == nil {
		return deny(domain.ErrDestinationNotAllowlisted, "destination address is not on vault allowlist: "+norm.DestinationAddress)
	}

	// Single transfer limit (both asset-wide and per-destination cap).
	if norm.Amount > assetPolicy.MaxSingleTransfer {
		return deny(domain.ErrAmountLimitExceeded, fmt.Sprintf("amount %d exceeds asset max_single_transfer %d", norm.Amount, assetPolicy.MaxSingleTransfer))
	}
	if norm.Amount > matchedDest.MaxSingleTransfer {
		return deny(domain.ErrAmountLimitExceeded, fmt.Sprintf("amount %d exceeds destination max_single_transfer %d", norm.Amount, matchedDest.MaxSingleTransfer))
	}

	// Overflow-safe daily velocity check.
	if dailySpent < 0 || norm.Amount > assetPolicy.DailyLimit-dailySpent {
		return deny(domain.ErrDailyLimitExceeded, fmt.Sprintf("transfer would exceed daily limit %d (already spent %d)", assetPolicy.DailyLimit, dailySpent))
	}

	// Determine tiered approval quorum and eligible independent approvers (excluding requester).
	requiredApprovals := assetPolicy.StandardApprovalQuorum
	if assetPolicy.HighValueThreshold > 0 && norm.Amount >= assetPolicy.HighValueThreshold {
		requiredApprovals = assetPolicy.HighValueApprovalQuorum
	}

	eligible := make([]string, 0, len(e.cfg.Approvers))
	for _, a := range e.cfg.Approvers {
		if a.Active && a.ID != norm.RequestedBy {
			eligible = append(eligible, a.ID)
		}
	}
	sort.Strings(eligible)
	if len(eligible) < requiredApprovals {
		return deny(domain.ErrInsufficientApprovals, fmt.Sprintf("fewer eligible independent approvers (%d) than required quorum (%d)", len(eligible), requiredApprovals))
	}

	decision.Allowed = true
	decision.Reason = "allowed by custody policy"
	decision.RequiredApprovals = requiredApprovals
	decision.RequiredSigners = vault.SigningThreshold
	decision.EligibleApprovers = eligible
	return decision, nil
}
