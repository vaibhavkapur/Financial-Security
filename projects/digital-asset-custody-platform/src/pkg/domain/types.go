package domain

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

const (
	CurrentSchemaVersion = "1.0.0"
	IntentHashDomain     = "CUSTODY_INTENT_V1:"
	ApprovalSignDomain   = "CUSTODY_APPROVAL_V1:"
	TxSignDomain         = "CUSTODY_TX_V1:"
)

var (
	evmAddressRegex     = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	testnetBtcAddrRegex = regexp.MustCompile(`^(tb1[0-9a-z]{25,59}|[mn2][1-9A-HJ-NP-Za-km-z]{25,34})$`)
)

// Clock abstracts time retrieval for deterministic testing and replayability.
type Clock interface {
	Now() time.Time
}

// RealClock returns current UTC time.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now().UTC() }

// FixedClock provides deterministic UTC timestamps that can be explicitly advanced.
type FixedClock struct {
	current time.Time
}

func NewFixedClock(t time.Time) *FixedClock {
	return &FixedClock{current: t.UTC()}
}

func (c *FixedClock) Now() time.Time { return c.current }

func (c *FixedClock) Advance(d time.Duration) time.Time {
	c.current = c.current.Add(d).UTC()
	return c.current
}

func (c *FixedClock) Set(t time.Time) {
	c.current = t.UTC()
}

// IntentStatus enumerates the lifecycle states of a custody transfer intent.
type IntentStatus string

const (
	StatusPendingApproval        IntentStatus = "PENDING_APPROVAL"
	StatusDenied                 IntentStatus = "DENIED"
	StatusApproved               IntentStatus = "APPROVED"
	StatusSigned                 IntentStatus = "SIGNED"
	StatusBroadcast              IntentStatus = "BROADCAST"
	StatusConfirming             IntentStatus = "CONFIRMING"
	StatusConfirmed              IntentStatus = "CONFIRMED"
	StatusInvalidatedKeyRotation IntentStatus = "INVALIDATED_KEY_ROTATION"
	StatusReorgedDropped         IntentStatus = "REORGED_DROPPED"
	StatusFailed                 IntentStatus = "FAILED"
)

// TransferIntent is the canonical custody transfer request contract.
// Monetary amounts are represented strictly in integer minor units (e.g., gwei, micro_usdc, satoshi).
type TransferIntent struct {
	SchemaVersion      string `json:"schema_version"`
	IntentID           string `json:"intent_id"`
	VaultID            string `json:"vault_id"`
	Network            string `json:"network"`
	Asset              string `json:"asset"`
	Unit               string `json:"unit"`
	Amount             int64  `json:"amount"`
	SourceAddress      string `json:"source_address"`
	DestinationAddress string `json:"destination_address"`
	Nonce              uint64 `json:"nonce"`
	RequestedBy        string `json:"requested_by"`
	CreatedAt          string `json:"created_at"`
	ExpiresAt          string `json:"expires_at"`
	KeyEpoch           uint64 `json:"key_epoch"`
	Memo               string `json:"memo"`
}

// Normalize lowercases EVM addresses and normalizes timestamps to UTC RFC3339 format.
func (t *TransferIntent) Normalize() {
	t.Network = strings.TrimSpace(strings.ToLower(t.Network))
	t.Asset = strings.TrimSpace(strings.ToUpper(t.Asset))
	t.Unit = strings.TrimSpace(strings.ToLower(t.Unit))
	if strings.HasPrefix(t.SourceAddress, "0x") || strings.HasPrefix(t.SourceAddress, "0X") {
		t.SourceAddress = strings.ToLower(strings.TrimSpace(t.SourceAddress))
	} else {
		t.SourceAddress = strings.TrimSpace(t.SourceAddress)
	}
	if strings.HasPrefix(t.DestinationAddress, "0x") || strings.HasPrefix(t.DestinationAddress, "0X") {
		t.DestinationAddress = strings.ToLower(strings.TrimSpace(t.DestinationAddress))
	} else {
		t.DestinationAddress = strings.TrimSpace(t.DestinationAddress)
	}
	if parsed, err := time.Parse(time.RFC3339, t.CreatedAt); err == nil {
		t.CreatedAt = parsed.UTC().Format(time.RFC3339)
	}
	if parsed, err := time.Parse(time.RFC3339, t.ExpiresAt); err == nil {
		t.ExpiresAt = parsed.UTC().Format(time.RFC3339)
	}
}

// ValidateAddress checks address syntax for mock/testnet EVM or BTC formats.
func ValidateAddress(addr string) bool {
	return evmAddressRegex.MatchString(addr) || testnetBtcAddrRegex.MatchString(addr)
}

// ValidateBasic validates structural invariants of a TransferIntent independent of policy.
func (t TransferIntent) ValidateBasic(now time.Time) error {
	if t.SchemaVersion != CurrentSchemaVersion {
		return NewError(ErrInvalidSchema, "unsupported or missing schema_version; expected "+CurrentSchemaVersion)
	}
	if strings.TrimSpace(t.IntentID) == "" {
		return NewError(ErrInvalidSchema, "intent_id is required")
	}
	if strings.TrimSpace(t.VaultID) == "" {
		return NewError(ErrInvalidSchema, "vault_id is required")
	}
	if strings.TrimSpace(t.Network) == "" {
		return NewError(ErrUnsupportedNetwork, "network is required")
	}
	if strings.TrimSpace(t.Asset) == "" || strings.TrimSpace(t.Unit) == "" {
		return NewError(ErrUnsupportedAsset, "asset and unit are required")
	}
	if t.Amount <= 0 {
		return NewError(ErrInvalidAmount, "amount must be a positive integer in minor units")
	}
	if !ValidateAddress(t.SourceAddress) {
		return NewError(ErrInvalidAddress, "source_address is not a valid mock/testnet address")
	}
	if !ValidateAddress(t.DestinationAddress) {
		return NewError(ErrInvalidAddress, "destination_address is not a valid mock/testnet address")
	}
	if strings.EqualFold(t.SourceAddress, t.DestinationAddress) {
		return NewError(ErrInvalidAddress, "source_address and destination_address must differ")
	}
	if t.Nonce == 0 {
		return NewError(ErrNonceMismatch, "nonce must be >= 1")
	}
	if strings.TrimSpace(t.RequestedBy) == "" {
		return NewError(ErrUnauthorizedRequester, "requested_by is required")
	}
	if t.KeyEpoch == 0 {
		return NewError(ErrKeyEpochMismatch, "key_epoch must be >= 1")
	}
	created, err := time.Parse(time.RFC3339, t.CreatedAt)
	if err != nil {
		return WrapError(ErrInvalidTimestamp, "created_at must be valid RFC3339 UTC timestamp", err)
	}
	expires, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return WrapError(ErrInvalidTimestamp, "expires_at must be valid RFC3339 UTC timestamp", err)
	}
	if !expires.After(created) {
		return NewError(ErrInvalidTimestamp, "expires_at must be strictly after created_at")
	}
	if !now.IsZero() && now.After(expires) {
		return NewError(ErrExpiredIntent, "transfer intent has expired")
	}
	return nil
}

// CanonicalBytes serializes TransferIntent deterministically without HTML escaping or whitespace.
func (t TransferIntent) CanonicalBytes() ([]byte, error) {
	norm := t
	norm.Normalize()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(norm); err != nil {
		return nil, WrapError(ErrInvalidSchema, "failed to serialize canonical intent", err)
	}
	// Strip trailing newline added by json.Encoder.Encode
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	return out, nil
}

// ComputeHash returns the domain-separated SHA-256 hex digest of the canonical TransferIntent.
func (t TransferIntent) ComputeHash() (string, error) {
	canonical, err := t.CanonicalBytes()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(IntentHashDomain))
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyHash verifies that the canonical hash of the intent matches expectedHash in constant time.
func (t TransferIntent) VerifyHash(expectedHash string) error {
	actual, err := t.ComputeHash()
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(actual), []byte(strings.ToLower(expectedHash))) != 1 {
		return NewError(ErrIntentHashMismatch, "intent payload hash does not match approved intent hash").
			WithDetails(map[string]any{
				"expected_hash": expectedHash,
				"computed_hash": actual,
			})
	}
	return nil
}

// PolicyConfig defines the custody rules loaded from versioned JSON configuration.
type PolicyConfig struct {
	SchemaVersion     string                 `json:"schema_version"`
	PolicyVersion     string                 `json:"policy_version"`
	Environment       string                 `json:"environment"`
	AllowedNetworks   []string               `json:"allowed_networks"`
	ConfirmationDepth int                    `json:"confirmation_depth"`
	Vaults            map[string]VaultPolicy `json:"vaults"`
	Approvers         []ActorConfig          `json:"approvers"`
	Requesters        []ActorConfig          `json:"requesters"`
}

type VaultPolicy struct {
	VaultID              string                   `json:"vault_id"`
	Network              string                   `json:"network"`
	SourceAddress        string                   `json:"source_address"`
	Active               bool                     `json:"active"`
	SigningThreshold     int                      `json:"signing_threshold"`
	SignerIDs            []string                 `json:"signer_ids"`
	Assets               map[string]AssetPolicy   `json:"assets"`
	DestinationAllowlist []AllowlistedDestination `json:"destination_allowlist"`
}

type AssetPolicy struct {
	Unit                    string `json:"unit"`
	Decimals                int    `json:"decimals"`
	MaxSingleTransfer       int64  `json:"max_single_transfer"`
	DailyLimit              int64  `json:"daily_limit"`
	HighValueThreshold      int64  `json:"high_value_threshold"`
	StandardApprovalQuorum  int    `json:"standard_approval_quorum"`
	HighValueApprovalQuorum int    `json:"high_value_approval_quorum"`
}

type AllowlistedDestination struct {
	Address           string `json:"address"`
	Label             string `json:"label"`
	MaxSingleTransfer int64  `json:"max_single_transfer"`
}

type ActorConfig struct {
	ID     string `json:"id"`
	Role   string `json:"role"`
	Active bool   `json:"active"`
}

// PolicyDecision captures the immutable output of policy evaluation.
type PolicyDecision struct {
	Allowed           bool      `json:"allowed"`
	ReasonCode        ErrorCode `json:"reason_code,omitempty"`
	Reason            string    `json:"reason"`
	PolicyVersion     string    `json:"policy_version"`
	PolicyDigest      string    `json:"policy_digest"`
	RequiredApprovals int       `json:"required_approvals"`
	RequiredSigners   int       `json:"required_signers"`
	EligibleApprovers []string  `json:"eligible_approvers"`
	EvaluatedAt       string    `json:"evaluated_at"`
}

// ApprovalSignature represents one independent cryptographic approval bound to IntentHash.
type ApprovalSignature struct {
	ApproverID    string `json:"approver_id"`
	IntentHash    string `json:"intent_hash"`
	PolicyVersion string `json:"policy_version"`
	SignatureHex  string `json:"signature_hex"`
	ApprovedAt    string `json:"approved_at"`
}

// ApprovalCertificate binds an approved intent hash, policy decision, and quorum of approvals.
type ApprovalCertificate struct {
	IntentID       string              `json:"intent_id"`
	IntentHash     string              `json:"intent_hash"`
	KeyEpoch       uint64              `json:"key_epoch"`
	PolicyDecision PolicyDecision      `json:"policy_decision"`
	Approvals      []ApprovalSignature `json:"approvals"`
	CertifiedAt    string              `json:"certified_at"`
}

// SignerStatus represents online/offline availability of an isolated signer node.
type SignerStatus string

const (
	SignerOnline  SignerStatus = "ONLINE"
	SignerOffline SignerStatus = "OFFLINE"
)

// KeyEpochState records public signing keys for a vault at a specific rotation epoch.
// Private key material is never stored in domain structs.
type KeyEpochState struct {
	VaultID       string            `json:"vault_id"`
	KeyEpoch      uint64            `json:"key_epoch"`
	Threshold     int               `json:"threshold"`
	SignerPubKeys map[string]string `json:"signer_pubkeys"`
	Status        string            `json:"status"` // ACTIVE or RETIRED
	ActivatedAt   string            `json:"activated_at"`
	RetiredAt     string            `json:"retired_at,omitempty"`
}

// PartialSignature is an individual Ed25519 signature from an isolated signer node.
type PartialSignature struct {
	SignerID     string `json:"signer_id"`
	KeyEpoch     uint64 `json:"key_epoch"`
	IntentHash   string `json:"intent_hash"`
	SignatureHex string `json:"signature_hex"`
	SignedAt     string `json:"signed_at"`
}

// MultisigBundle aggregates threshold-verified partial signatures for a transfer intent.
type MultisigBundle struct {
	IntentID    string             `json:"intent_id"`
	IntentHash  string             `json:"intent_hash"`
	VaultID     string             `json:"vault_id"`
	KeyEpoch    uint64             `json:"key_epoch"`
	Nonce       uint64             `json:"nonce"`
	Threshold   int                `json:"threshold"`
	Signatures  []PartialSignature `json:"signatures"`
	TxHash      string             `json:"tx_hash"`
	AssembledAt string             `json:"assembled_at"`
}

// IntentRecord tracks the full custody lifecycle of a transfer intent.
type IntentRecord struct {
	Intent         TransferIntent       `json:"intent"`
	IntentHash     string               `json:"intent_hash"`
	Status         IntentStatus         `json:"status"`
	PolicyDecision PolicyDecision       `json:"policy_decision"`
	Approvals      []ApprovalSignature  `json:"approvals"`
	Certificate    *ApprovalCertificate `json:"certificate,omitempty"`
	Multisig       *MultisigBundle      `json:"multisig,omitempty"`
	TxHash         string               `json:"tx_hash,omitempty"`
	BlockHeight    uint64               `json:"block_height,omitempty"`
	BlockHash      string               `json:"block_hash,omitempty"`
	Confirmations  int                  `json:"confirmations"`
	FailureReason  string               `json:"failure_reason,omitempty"`
	UpdatedAt      string               `json:"updated_at"`
}

// VaultBalance represents ledger balances for a vault and asset in minor units.
type VaultBalance struct {
	VaultID          string `json:"vault_id"`
	Asset            string `json:"asset"`
	Unit             string `json:"unit"`
	ConfirmedBalance int64  `json:"confirmed_balance"`
	ReservedBalance  int64  `json:"reserved_balance"`
	AvailableBalance int64  `json:"available_balance"`
	UpdatedAt        string `json:"updated_at"`
}

// LedgerEntryType enumerates double-entry balance transitions.
type LedgerEntryType string

const (
	LedgerDeposit     LedgerEntryType = "DEPOSIT"
	LedgerReserve     LedgerEntryType = "RESERVE"
	LedgerRelease     LedgerEntryType = "RELEASE"
	LedgerSettle      LedgerEntryType = "SETTLE"
	LedgerReorgRevert LedgerEntryType = "REORG_REVERT"
)

// LedgerEntry is an immutable balance accounting event.
type LedgerEntry struct {
	EntryID        string          `json:"entry_id"`
	VaultID        string          `json:"vault_id"`
	Asset          string          `json:"asset"`
	IntentID       string          `json:"intent_id,omitempty"`
	Type           LedgerEntryType `json:"type"`
	DeltaConfirmed int64           `json:"delta_confirmed"`
	DeltaReserved  int64           `json:"delta_reserved"`
	BalanceAfter   int64           `json:"balance_after"`
	ReservedAfter  int64           `json:"reserved_after"`
	CreatedAt      string          `json:"created_at"`
}

// ChainTxStatus reflects mock testnet transaction state.
type ChainTxStatus string

const (
	ChainTxMempool   ChainTxStatus = "MEMPOOL"
	ChainTxIncluded  ChainTxStatus = "INCLUDED"
	ChainTxConfirmed ChainTxStatus = "CONFIRMED"
	ChainTxOrphaned  ChainTxStatus = "ORPHANED"
)

// ChainTransaction represents a signed transfer broadcast to the mock testnet.
type ChainTransaction struct {
	TxHash             string         `json:"tx_hash"`
	IntentID           string         `json:"intent_id"`
	IntentHash         string         `json:"intent_hash"`
	VaultID            string         `json:"vault_id"`
	Network            string         `json:"network"`
	Asset              string         `json:"asset"`
	Amount             int64          `json:"amount"`
	SourceAddress      string         `json:"source_address"`
	DestinationAddress string         `json:"destination_address"`
	Nonce              uint64         `json:"nonce"`
	KeyEpoch           uint64         `json:"key_epoch"`
	Bundle             MultisigBundle `json:"bundle"`
	Status             ChainTxStatus  `json:"status"`
	BlockHeight        uint64         `json:"block_height,omitempty"`
	BlockHash          string         `json:"block_hash,omitempty"`
	Confirmations      int            `json:"confirmations"`
}

// Block represents a deterministic mock testnet block.
type Block struct {
	Height     uint64   `json:"height"`
	Hash       string   `json:"hash"`
	ParentHash string   `json:"parent_hash"`
	ForkTag    string   `json:"fork_tag"`
	Timestamp  string   `json:"timestamp"`
	TxHashes   []string `json:"tx_hashes"`
}

// ReorgResult describes a simulated blockchain reorganization.
type ReorgResult struct {
	ReorgDepth        int      `json:"reorg_depth"`
	CommonAncestor    uint64   `json:"common_ancestor_height"`
	OrphanedBlocks    []string `json:"orphaned_block_hashes"`
	NewCanonicalTip   string   `json:"new_canonical_tip"`
	RequeuedTxHashes  []string `json:"requeued_tx_hashes"`
	DroppedTxHashes   []string `json:"dropped_tx_hashes"`
}

// VaultReconciliation captures reconciliation check for a single (vault, asset) pair.
type VaultReconciliation struct {
	VaultID                  string `json:"vault_id"`
	Asset                    string `json:"asset"`
	LedgerConfirmedBalance   int64  `json:"ledger_confirmed_balance"`
	OnChainConfirmedBalance  int64  `json:"onchain_confirmed_balance"`
	LedgerReservedBalance    int64  `json:"ledger_reserved_balance"`
	SumPendingReservedAmount int64  `json:"sum_pending_reserved_amount"`
	LedgerAvailableBalance   int64  `json:"ledger_available_balance"`
	BalanceDelta             int64  `json:"balance_delta"`
	ReservedDelta            int64  `json:"reserved_delta"`
	Matched                  bool   `json:"matched"`
}

// ReconciliationReport summarizes custody vs mock testnet chain consistency.
type ReconciliationReport struct {
	GeneratedAt     string                `json:"generated_at"`
	ChainHeight     uint64                `json:"chain_height"`
	ChainTipHash    string                `json:"chain_tip_hash"`
	Reconciled      bool                  `json:"reconciled"`
	AuditChainValid bool                  `json:"audit_chain_valid"`
	VaultChecks     []VaultReconciliation `json:"vault_checks"`
	Discrepancies   []string              `json:"discrepancies,omitempty"`
	Checksum        string                `json:"checksum"`
}

// AuditEvent is a tamper-evident, hash-chained audit record.
type AuditEvent struct {
	Seq        uint64         `json:"seq"`
	Timestamp  string         `json:"timestamp"`
	EventType  string         `json:"event_type"`
	Actor      string         `json:"actor"`
	IntentID   string         `json:"intent_id,omitempty"`
	Outcome    string         `json:"outcome"`
	ReasonCode ErrorCode      `json:"reason_code,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
	PrevHash   string         `json:"prev_hash"`
	EventHash  string         `json:"event_hash"`
}
