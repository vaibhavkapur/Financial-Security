package signer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/financial-security/digital-asset-custody-platform/src/pkg/domain"
)

// DeriveTestKeypair deterministically derives an Ed25519 keypair from a mock/testnet seed.
// Scope: Educational/offline prototype only; never use deterministic seeds for production funds.
func DeriveTestKeypair(masterSeed, roleTag, actorID string, epoch uint64) (ed25519.PublicKey, ed25519.PrivateKey) {
	material := fmt.Sprintf("TESTNET_MOCK_SEED:%s:%s:%s:%d", masterSeed, roleTag, actorID, epoch)
	seed32 := sha256.Sum256([]byte(material))
	priv := ed25519.NewKeyFromSeed(seed32[:])
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

// ApprovalMessage constructs the canonical domain-separated bytes signed by an independent approver.
func ApprovalMessage(intentHash, approverID, policyVersion string) []byte {
	return []byte(fmt.Sprintf("%s%s:%s:%s", domain.ApprovalSignDomain, strings.ToLower(intentHash), approverID, policyVersion))
}

// TxSignMessage constructs the canonical domain-separated bytes signed by an isolated vault signer node.
func TxSignMessage(intentHash string, keyEpoch, nonce uint64) []byte {
	return []byte(fmt.Sprintf("%s%s:%d:%d", domain.TxSignDomain, strings.ToLower(intentHash), keyEpoch, nonce))
}

// ApproverKeyring simulates isolated approver devices that hold independent Ed25519 approval keys.
// Private keys are unexported and never serialized.
type ApproverKeyring struct {
	mu      sync.RWMutex
	privs   map[string]ed25519.PrivateKey
	pubKeys map[string]ed25519.PublicKey
}

// String redacts private material in formatted output.
func (k *ApproverKeyring) String() string {
	return fmt.Sprintf("ApproverKeyring{count=%d, keys=[REDACTED]}", len(k.pubKeys))
}

// NewApproverKeyring initializes deterministic test Ed25519 keys for all configured approvers.
func NewApproverKeyring(masterSeed string, approvers []domain.ActorConfig) *ApproverKeyring {
	kr := &ApproverKeyring{
		privs:   make(map[string]ed25519.PrivateKey, len(approvers)),
		pubKeys: make(map[string]ed25519.PublicKey, len(approvers)),
	}
	for _, a := range approvers {
		pub, priv := DeriveTestKeypair(masterSeed, "APPROVER", a.ID, 1)
		kr.privs[a.ID] = priv
		kr.pubKeys[a.ID] = pub
	}
	return kr
}

// PublicKeys returns a copy of approver public keys safe to distribute to policy, ledger, and signer boundaries.
func (k *ApproverKeyring) PublicKeys() map[string]ed25519.PublicKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make(map[string]ed25519.PublicKey, len(k.pubKeys))
	for id, pk := range k.pubKeys {
		cp := make(ed25519.PublicKey, len(pk))
		copy(cp, pk)
		out[id] = cp
	}
	return out
}

// SignApproval produces an Ed25519 approval signature bound to the exact intent hash and policy version.
func (k *ApproverKeyring) SignApproval(approverID, intentHash, policyVersion string, now time.Time) (domain.ApprovalSignature, error) {
	k.mu.RLock()
	priv, ok := k.privs[approverID]
	k.mu.RUnlock()
	if !ok {
		return domain.ApprovalSignature{}, domain.NewError(domain.ErrUnauthorizedApprover, "unknown approver key: "+approverID)
	}
	msg := ApprovalMessage(intentHash, approverID, policyVersion)
	sig := ed25519.Sign(priv, msg)
	return domain.ApprovalSignature{
		ApproverID:    approverID,
		IntentHash:    strings.ToLower(intentHash),
		PolicyVersion: policyVersion,
		SignatureHex:  hex.EncodeToString(sig),
		ApprovedAt:    now.UTC().Format(time.RFC3339),
	}, nil
}

// VerifyApprovalSignature validates a single approver's Ed25519 signature over the canonical intent hash.
func VerifyApprovalSignature(pubKeys map[string]ed25519.PublicKey, expectedIntentHash, expectedPolicyVersion string, approval domain.ApprovalSignature) error {
	pub, ok := pubKeys[approval.ApproverID]
	if !ok {
		return domain.NewError(domain.ErrUnauthorizedApprover, "approver public key not registered: "+approval.ApproverID)
	}
	if !strings.EqualFold(approval.IntentHash, expectedIntentHash) {
		return domain.NewError(domain.ErrIntentHashMismatch, "approval intent_hash does not match target intent_hash")
	}
	if approval.PolicyVersion != expectedPolicyVersion {
		return domain.NewError(domain.ErrPolicyDenied, "approval policy_version does not match active policy decision")
	}
	sigBytes, err := hex.DecodeString(approval.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return domain.NewError(domain.ErrInvalidSignature, "malformed Ed25519 approval signature from "+approval.ApproverID)
	}
	msg := ApprovalMessage(expectedIntentHash, approval.ApproverID, expectedPolicyVersion)
	if !ed25519.Verify(pub, msg, sigBytes) {
		return domain.NewError(domain.ErrInvalidSignature, "invalid Ed25519 approval signature from "+approval.ApproverID)
	}
	return nil
}

// SignRequest is the strictly typed cross-boundary payload sent from custody orchestration to isolated signers.
type SignRequest struct {
	Intent      domain.TransferIntent      `json:"intent"`
	Certificate domain.ApprovalCertificate `json:"certificate"`
}

// SignerNode represents an isolated signing boundary (mock HSM/enclave node).
// It has zero access to ledger balances or mutable policy configs; it independently verifies
// intent integrity, approval signatures, quorum, key epoch, expiry, and local replay state.
type SignerNode struct {
	mu                   sync.Mutex
	signerID             string
	masterSeed           string
	online               bool
	vaultEpochs          map[string]uint64
	privKeys             map[string]map[uint64]ed25519.PrivateKey // vaultID -> epoch -> privKey (unexported)
	pubKeys              map[string]map[uint64]ed25519.PublicKey  // vaultID -> epoch -> pubKey
	trustedApprovers     map[string]ed25519.PublicKey
	trustedPolicyVersion string
	signedIntentIDs      map[string]bool
	signedVaultNonces    map[string]bool
}

// String ensures no private key material is ever printed.
func (n *SignerNode) String() string {
	return fmt.Sprintf("SignerNode{id=%s, online=%v, keys=[REDACTED]}", n.signerID, n.online)
}

func newSignerNode(signerID, masterSeed, policyVersion string, trustedApprovers map[string]ed25519.PublicKey) *SignerNode {
	return &SignerNode{
		signerID:             signerID,
		masterSeed:           masterSeed,
		online:               true,
		vaultEpochs:          make(map[string]uint64),
		privKeys:             make(map[string]map[uint64]ed25519.PrivateKey),
		pubKeys:              make(map[string]map[uint64]ed25519.PublicKey),
		trustedApprovers:     trustedApprovers,
		trustedPolicyVersion: policyVersion,
		signedIntentIDs:      make(map[string]bool),
		signedVaultNonces:    make(map[string]bool),
	}
}

func (n *SignerNode) initVaultEpoch(vaultID string, epoch uint64) ed25519.PublicKey {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.privKeys[vaultID] == nil {
		n.privKeys[vaultID] = make(map[uint64]ed25519.PrivateKey)
		n.pubKeys[vaultID] = make(map[uint64]ed25519.PublicKey)
	}
	pub, priv := DeriveTestKeypair(n.masterSeed, "VAULT_SIGNER:"+vaultID, n.signerID, epoch)
	n.privKeys[vaultID][epoch] = priv
	n.pubKeys[vaultID][epoch] = pub
	n.vaultEpochs[vaultID] = epoch
	return pub
}

func (n *SignerNode) setOnline(online bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.online = online
}

func (n *SignerNode) isOnline() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.online
}

// Sign independently verifies every security invariant before producing a partial Ed25519 signature.
func (n *SignerNode) Sign(req SignRequest, now time.Time) (domain.PartialSignature, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.online {
		return domain.PartialSignature{}, domain.NewError(domain.ErrSignerOffline, "isolated signer node is offline: "+n.signerID)
	}

	intent := req.Intent
	intent.Normalize()
	if err := intent.ValidateBasic(now); err != nil {
		return domain.PartialSignature{}, err
	}

	// 1. Recompute canonical intent hash independently to detect any payload tampering (e.g., tampered destination).
	computedHash, err := intent.ComputeHash()
	if err != nil {
		return domain.PartialSignature{}, err
	}
	if err := intent.VerifyHash(req.Certificate.IntentHash); err != nil {
		return domain.PartialSignature{}, err
	}
	if req.Certificate.IntentID != intent.IntentID {
		return domain.PartialSignature{}, domain.NewError(domain.ErrIntentHashMismatch, "certificate intent_id mismatch")
	}

	// 2. Enforce active key epoch; reject stale or future epochs.
	activeEpoch, ok := n.vaultEpochs[intent.VaultID]
	if !ok {
		return domain.PartialSignature{}, domain.NewError(domain.ErrUnknownVault, "signer has no key material for vault "+intent.VaultID)
	}
	if intent.KeyEpoch != activeEpoch || req.Certificate.KeyEpoch != activeEpoch {
		return domain.PartialSignature{}, domain.NewError(domain.ErrKeyEpochMismatch,
			fmt.Sprintf("intent key_epoch %d does not match active signer epoch %d", intent.KeyEpoch, activeEpoch))
	}

	// 3. Enforce policy allow decision and trusted policy version.
	if !req.Certificate.PolicyDecision.Allowed {
		return domain.PartialSignature{}, domain.NewError(domain.ErrPolicyDenied, "refusing to sign intent without ALLOW policy decision")
	}
	if req.Certificate.PolicyDecision.PolicyVersion != n.trustedPolicyVersion {
		return domain.PartialSignature{}, domain.NewError(domain.ErrPolicyDenied, "untrusted policy_version in approval certificate")
	}

	// 4. Independently verify approval quorum, separation of duties, uniqueness, and Ed25519 signatures.
	required := req.Certificate.PolicyDecision.RequiredApprovals
	if required < 1 {
		return domain.PartialSignature{}, domain.NewError(domain.ErrInsufficientApprovals, "invalid required approval quorum")
	}
	eligibleSet := make(map[string]bool, len(req.Certificate.PolicyDecision.EligibleApprovers))
	for _, a := range req.Certificate.PolicyDecision.EligibleApprovers {
		eligibleSet[a] = true
	}

	seenApprovers := make(map[string]bool, len(req.Certificate.Approvals))
	validCount := 0
	for _, appr := range req.Certificate.Approvals {
		if appr.ApproverID == intent.RequestedBy {
			return domain.PartialSignature{}, domain.NewError(domain.ErrSelfApprovalForbidden, "requester cannot approve own transfer intent")
		}
		if !eligibleSet[appr.ApproverID] {
			return domain.PartialSignature{}, domain.NewError(domain.ErrUnauthorizedApprover, "approver is not in eligible policy set: "+appr.ApproverID)
		}
		if seenApprovers[appr.ApproverID] {
			return domain.PartialSignature{}, domain.NewError(domain.ErrDuplicateApproval, "duplicate approval from "+appr.ApproverID)
		}
		if err := VerifyApprovalSignature(n.trustedApprovers, computedHash, req.Certificate.PolicyDecision.PolicyVersion, appr); err != nil {
			return domain.PartialSignature{}, err
		}
		seenApprovers[appr.ApproverID] = true
		validCount++
	}
	if validCount < required {
		return domain.PartialSignature{}, domain.NewError(domain.ErrInsufficientApprovals,
			fmt.Sprintf("insufficient valid approvals: got %d, required %d", validCount, required))
	}

	// 5. Enforce local signer-side replay protection (intent ID + vault/nonce pair).
	nonceKey := intent.VaultID + ":" + strconv.FormatUint(intent.Nonce, 10)
	if n.signedIntentIDs[intent.IntentID] || n.signedVaultNonces[nonceKey] {
		return domain.PartialSignature{}, domain.NewError(domain.ErrReplayDetected,
			fmt.Sprintf("signer %s detected replay for intent %s / nonce %d", n.signerID, intent.IntentID, intent.Nonce))
	}

	priv := n.privKeys[intent.VaultID][activeEpoch]
	msg := TxSignMessage(computedHash, activeEpoch, intent.Nonce)
	sig := ed25519.Sign(priv, msg)

	n.signedIntentIDs[intent.IntentID] = true
	n.signedVaultNonces[nonceKey] = true

	return domain.PartialSignature{
		SignerID:     n.signerID,
		KeyEpoch:     activeEpoch,
		IntentHash:   computedHash,
		SignatureHex: hex.EncodeToString(sig),
		SignedAt:     now.UTC().Format(time.RFC3339),
	}, nil
}

// MockMultisigCluster manages a threshold T-of-N set of isolated SignerNodes.
type MockMultisigCluster struct {
	mu            sync.RWMutex
	masterSeed    string
	nodes         map[string]*SignerNode
	vaultSigners  map[string][]string
	vaultThresh   map[string]int
	vaultEpochs   map[string]uint64
	epochHistory  map[string]map[uint64]domain.KeyEpochState
}

// NewMockMultisigCluster provisions isolated T-of-N signer nodes for all configured vaults.
func NewMockMultisigCluster(masterSeed string, cfg domain.PolicyConfig, approverPubKeys map[string]ed25519.PublicKey, now time.Time) *MockMultisigCluster {
	c := &MockMultisigCluster{
		masterSeed:   masterSeed,
		nodes:        make(map[string]*SignerNode),
		vaultSigners: make(map[string][]string),
		vaultThresh:  make(map[string]int),
		vaultEpochs:  make(map[string]uint64),
		epochHistory: make(map[string]map[uint64]domain.KeyEpochState),
	}

	for vaultID, vp := range cfg.Vaults {
		signers := append([]string(nil), vp.SignerIDs...)
		sort.Strings(signers)
		c.vaultSigners[vaultID] = signers
		c.vaultThresh[vaultID] = vp.SigningThreshold
		c.vaultEpochs[vaultID] = 1
		c.epochHistory[vaultID] = make(map[uint64]domain.KeyEpochState)

		pubMap := make(map[string]string, len(signers))
		for _, sid := range signers {
			node, ok := c.nodes[sid]
			if !ok {
				node = newSignerNode(sid, masterSeed, cfg.PolicyVersion, approverPubKeys)
				c.nodes[sid] = node
			}
			pub := node.initVaultEpoch(vaultID, 1)
			pubMap[sid] = hex.EncodeToString(pub)
		}
		c.epochHistory[vaultID][1] = domain.KeyEpochState{
			VaultID:       vaultID,
			KeyEpoch:      1,
			Threshold:     vp.SigningThreshold,
			SignerPubKeys: pubMap,
			Status:        "ACTIVE",
			ActivatedAt:   now.UTC().Format(time.RFC3339),
		}
	}
	return c
}

// SetNodeOnline toggles an isolated signer node online/offline to simulate signer outages and recovery.
func (c *MockMultisigCluster) SetNodeOnline(signerID string, online bool) error {
	c.mu.RLock()
	node, ok := c.nodes[signerID]
	c.mu.RUnlock()
	if !ok {
		return domain.NewError(domain.ErrInvalidConfig, "unknown signer_id: "+signerID)
	}
	node.setOnline(online)
	return nil
}

// ActiveKeyEpoch returns the active key epoch for a vault.
func (c *MockMultisigCluster) ActiveKeyEpoch(vaultID string) (uint64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	epoch, ok := c.vaultEpochs[vaultID]
	if !ok {
		return 0, domain.NewError(domain.ErrUnknownVault, "unknown vault_id: "+vaultID)
	}
	return epoch, nil
}

// GetKeyEpochState returns public key metadata for a given vault and epoch (active or retired).
func (c *MockMultisigCluster) GetKeyEpochState(vaultID string, epoch uint64) (domain.KeyEpochState, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	m, ok := c.epochHistory[vaultID]
	if !ok {
		return domain.KeyEpochState{}, domain.NewError(domain.ErrUnknownVault, "unknown vault_id: "+vaultID)
	}
	st, ok := m[epoch]
	if !ok {
		return domain.KeyEpochState{}, domain.NewError(domain.ErrKeyEpochMismatch, "unknown key epoch")
	}
	return st, nil
}

// RotateVaultKeys retires the current key epoch and activates epoch+1 across all signer nodes.
// Historical public keys remain available read-only for confirming/reconciling prior transactions.
func (c *MockMultisigCluster) RotateVaultKeys(vaultID string, now time.Time) (domain.KeyEpochState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldEpoch, ok := c.vaultEpochs[vaultID]
	if !ok {
		return domain.KeyEpochState{}, domain.NewError(domain.ErrUnknownVault, "unknown vault_id: "+vaultID)
	}
	newEpoch := oldEpoch + 1
	nowStr := now.UTC().Format(time.RFC3339)

	// Retire previous epoch state.
	prev := c.epochHistory[vaultID][oldEpoch]
	prev.Status = "RETIRED"
	prev.RetiredAt = nowStr
	c.epochHistory[vaultID][oldEpoch] = prev

	pubMap := make(map[string]string, len(c.vaultSigners[vaultID]))
	for _, sid := range c.vaultSigners[vaultID] {
		pub := c.nodes[sid].initVaultEpoch(vaultID, newEpoch)
		pubMap[sid] = hex.EncodeToString(pub)
	}
	newState := domain.KeyEpochState{
		VaultID:       vaultID,
		KeyEpoch:      newEpoch,
		Threshold:     c.vaultThresh[vaultID],
		SignerPubKeys: pubMap,
		Status:        "ACTIVE",
		ActivatedAt:   nowStr,
	}
	c.vaultEpochs[vaultID] = newEpoch
	c.epochHistory[vaultID][newEpoch] = newState
	return newState, nil
}

// RestoreReplayState repopulates signer replay caches and key epoch state after a process restart.
func (c *MockMultisigCluster) RestoreState(vaultEpochs map[string]uint64, signedRecords []domain.IntentRecord, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for vaultID, targetEpoch := range vaultEpochs {
		cur := c.vaultEpochs[vaultID]
		for cur < targetEpoch {
			prev := c.epochHistory[vaultID][cur]
			prev.Status = "RETIRED"
			prev.RetiredAt = now.UTC().Format(time.RFC3339)
			c.epochHistory[vaultID][cur] = prev

			cur++
			pubMap := make(map[string]string, len(c.vaultSigners[vaultID]))
			for _, sid := range c.vaultSigners[vaultID] {
				pub := c.nodes[sid].initVaultEpoch(vaultID, cur)
				pubMap[sid] = hex.EncodeToString(pub)
			}
			c.epochHistory[vaultID][cur] = domain.KeyEpochState{
				VaultID:       vaultID,
				KeyEpoch:      cur,
				Threshold:     c.vaultThresh[vaultID],
				SignerPubKeys: pubMap,
				Status:        "ACTIVE",
				ActivatedAt:   now.UTC().Format(time.RFC3339),
			}
		}
		c.vaultEpochs[vaultID] = targetEpoch
	}

	for _, rec := range signedRecords {
		if rec.Multisig == nil {
			continue
		}
		nonceKey := rec.Intent.VaultID + ":" + strconv.FormatUint(rec.Intent.Nonce, 10)
		for _, ps := range rec.Multisig.Signatures {
			if node, ok := c.nodes[ps.SignerID]; ok {
				node.mu.Lock()
				node.signedIntentIDs[rec.Intent.IntentID] = true
				node.signedVaultNonces[nonceKey] = true
				node.mu.Unlock()
			}
		}
	}
}

// RequestMultisig collects threshold T-of-N partial signatures from isolated signer nodes.
// Security/validation rejections (tampered hash, missing quorum, replay, key epoch mismatch)
// fail closed immediately; offline nodes are skipped unless available signers drop below threshold.
func (c *MockMultisigCluster) RequestMultisig(req SignRequest, now time.Time) (domain.MultisigBundle, error) {
	c.mu.RLock()
	signers, ok := c.vaultSigners[req.Intent.VaultID]
	threshold := c.vaultThresh[req.Intent.VaultID]
	c.mu.RUnlock()
	if !ok {
		return domain.MultisigBundle{}, domain.NewError(domain.ErrUnknownVault, "unknown vault_id: "+req.Intent.VaultID)
	}

	// Pre-check online signer count so we never partially mutate replay caches when quorum is impossible.
	onlineNodes := make([]*SignerNode, 0, len(signers))
	offlineIDs := make([]string, 0)
	for _, sid := range signers {
		c.mu.RLock()
		node := c.nodes[sid]
		c.mu.RUnlock()
		if node.isOnline() {
			onlineNodes = append(onlineNodes, node)
		} else {
			offlineIDs = append(offlineIDs, sid)
		}
	}
	if len(onlineNodes) < threshold {
		return domain.MultisigBundle{}, domain.NewError(domain.ErrSignerQuorumUnavailable,
			fmt.Sprintf("only %d of %d required signers online (offline: %v)", len(onlineNodes), threshold, offlineIDs)).
			WithDetails(map[string]any{
				"online_count":    len(onlineNodes),
				"required":        threshold,
				"offline_signers": offlineIDs,
			})
	}

	partials := make([]domain.PartialSignature, 0, threshold)
	for _, node := range onlineNodes {
		if len(partials) >= threshold {
			break
		}
		ps, err := node.Sign(req, now)
		if err != nil {
			if domain.CodeOf(err) == domain.ErrSignerOffline {
				continue
			}
			// Any cryptographic, policy, tampering, epoch, or replay error fails closed immediately.
			return domain.MultisigBundle{}, err
		}
		partials = append(partials, ps)
	}

	if len(partials) < threshold {
		return domain.MultisigBundle{}, domain.NewError(domain.ErrSignerQuorumUnavailable,
			fmt.Sprintf("collected %d signatures, required threshold %d", len(partials), threshold))
	}

	sort.Slice(partials, func(i, j int) bool {
		return partials[i].SignerID < partials[j].SignerID
	})

	intentHash, err := req.Intent.ComputeHash()
	if err != nil {
		return domain.MultisigBundle{}, err
	}
	txHash := computeTxHash(intentHash, req.Intent.KeyEpoch, req.Intent.Nonce, partials)

	bundle := domain.MultisigBundle{
		IntentID:    req.Intent.IntentID,
		IntentHash:  intentHash,
		VaultID:     req.Intent.VaultID,
		KeyEpoch:    req.Intent.KeyEpoch,
		Nonce:       req.Intent.Nonce,
		Threshold:   threshold,
		Signatures:  partials,
		TxHash:      txHash,
		AssembledAt: now.UTC().Format(time.RFC3339),
	}

	if err := c.VerifyBundle(req.Intent, bundle); err != nil {
		return domain.MultisigBundle{}, err
	}
	return bundle, nil
}

// VerifyBundle verifies every Ed25519 signature in a MultisigBundle against the vault's recorded KeyEpochState.
func (c *MockMultisigCluster) VerifyBundle(intent domain.TransferIntent, bundle domain.MultisigBundle) error {
	if err := intent.VerifyHash(bundle.IntentHash); err != nil {
		return err
	}
	epochState, err := c.GetKeyEpochState(intent.VaultID, bundle.KeyEpoch)
	if err != nil {
		return err
	}
	if len(bundle.Signatures) < epochState.Threshold {
		return domain.NewError(domain.ErrSignerQuorumUnavailable, "multisig bundle has fewer signatures than vault threshold")
	}
	msg := TxSignMessage(bundle.IntentHash, bundle.KeyEpoch, intent.Nonce)
	seen := make(map[string]bool, len(bundle.Signatures))
	for _, ps := range bundle.Signatures {
		if seen[ps.SignerID] {
			return domain.NewError(domain.ErrInvalidSignature, "duplicate signer in multisig bundle: "+ps.SignerID)
		}
		pubHex, ok := epochState.SignerPubKeys[ps.SignerID]
		if !ok {
			return domain.NewError(domain.ErrInvalidSignature, "signer not authorized for vault epoch: "+ps.SignerID)
		}
		pubBytes, err := hex.DecodeString(pubHex)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			return domain.NewError(domain.ErrInvalidSignature, "corrupt signer public key")
		}
		sigBytes, err := hex.DecodeString(ps.SignatureHex)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			return domain.NewError(domain.ErrInvalidSignature, "malformed Ed25519 partial signature from "+ps.SignerID)
		}
		if !ed25519.Verify(ed25519.PublicKey(pubBytes), msg, sigBytes) {
			return domain.NewError(domain.ErrInvalidSignature, "invalid Ed25519 partial signature from "+ps.SignerID)
		}
		seen[ps.SignerID] = true
	}
	return nil
}

func computeTxHash(intentHash string, keyEpoch, nonce uint64, partials []domain.PartialSignature) string {
	h := sha256.New()
	h.Write([]byte("CUSTODY_TX_HASH_V1:"))
	h.Write([]byte(intentHash))
	h.Write([]byte(fmt.Sprintf(":%d:%d", keyEpoch, nonce)))
	for _, ps := range partials {
		h.Write([]byte("|" + ps.SignerID + ":" + ps.SignatureHex))
	}
	return "0x" + hex.EncodeToString(h.Sum(nil))
}
