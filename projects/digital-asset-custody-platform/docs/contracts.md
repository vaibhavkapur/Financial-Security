# Data Contracts — Digital Asset Custody Platform

**Schema Version:** `1.0.0`  
**Monetary Units:** Strictly positive 64-bit signed integers (`int64`) in asset minor units (no floating-point arithmetic anywhere in the domain).  
**Timestamps:** UTC RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).

## 1. Canonical Inputs

### 1.1 `TransferIntent`
Represented by `domain.TransferIntent` in `src/pkg/domain/types.go`:

| Field | Type | Constraints / Semantics |
|---|---|---|
| `schema_version` | `string` | Must equal `"1.0.0"` |
| `intent_id` | `string` | Unique non-empty caller identifier (replay-checked) |
| `vault_id` | `string` | Must reference an active vault in policy config |
| `network` | `string` | Normalized lowercase; must match vault network and be mock/testnet (`mock-*`, `*-testnet`, `*-sepolia`); `mainnet`/`production` rejected |
| `asset` | `string` | Normalized uppercase (e.g., `MOCK_ETH`, `MOCK_USDC`) |
| `unit` | `string` | Minor unit name matching policy (`gwei`, `micro_usdc`, `satoshi`) |
| `amount` | `int64` | Strictly `> 0`; checked against asset cap, destination cap, daily cap, and available balance |
| `source_address` | `string` | Valid mock/testnet EVM (`^0x[0-9a-fA-F]{40}$`) or BTC testnet address matching vault config |
| `destination_address` | `string` | Valid address, distinct from `source_address`, must appear on vault `destination_allowlist` |
| `nonce` | `uint64` | Strictly sequential per vault starting at `1` |
| `requested_by` | `string` | Must be an active requester; cannot approve own intent |
| `created_at` | `string` | RFC 3339 UTC timestamp |
| `expires_at` | `string` | RFC 3339 UTC timestamp strictly after `created_at` and `>= now` |
| `key_epoch` | `uint64` | Must equal vault's active `KeyEpoch` (`>= 1`) |
| `memo` | `string` | Optional non-sensitive metadata string |

### 1.2 Canonical Intent Hash Specification
```text
IntentHash = hex(SHA-256("CUSTODY_INTENT_V1:" || canonical_json(normalize(TransferIntent))))
```
- `normalize`: lowercase `network`, `unit`, and `0x` addresses; uppercase `asset`; UTC RFC 3339 timestamps.
- `canonical_json`: compact UTF-8 JSON with fixed field order matching `domain.TransferIntent`, no HTML escaping, no trailing newline.
- Reference vector (`data/fixtures/reference_fixture.json`):
  - `IntentHash = 77fed00728a365eb0a7554623e56feee1fd5cc6a90fc2e502096f2a505bff7ef` (verified independently via Python `hashlib.sha256` oracle in `data/fixtures/expected_reference_output.json`).

### 1.3 Cryptographic Signature Domain Separators
- **Independent Approval Signature (`ApprovalSignature`):**
  - Message: `"CUSTODY_APPROVAL_V1:" || intent_hash || ":" || approver_id || ":" || policy_version`
  - Algorithm: Ed25519 (`crypto/ed25519`)
- **Isolated Signer Partial Signature (`PartialSignature`):**
  - Message: `"CUSTODY_TX_V1:" || intent_hash || ":" || key_epoch || ":" || nonce`
  - Algorithm: Ed25519 (`crypto/ed25519`)
- **Deterministic Transaction Hash (`MultisigBundle.TxHash`):**
  - `"0x" || hex(SHA-256("CUSTODY_TX_HASH_V1:" || intent_hash || ":" || key_epoch || ":" || nonce || sorted("|" || signer_id || ":" || sig_hex)))`

### 1.4 Policy Configuration (`config/default-policy.json`)
Defines `policy_version`, `environment` (must not contain `prod` or `mainnet`), `allowed_networks`, `confirmation_depth`, `vaults` (signing threshold, signer IDs, assets with single/daily/high-value thresholds and approval quorums, destination allowlist), `approvers`, and `requesters`.

## 2. Canonical Outputs

### 2.1 `IntentRecord` Lifecycle States
`PENDING_APPROVAL` -> `APPROVED` -> `SIGNED` -> `BROADCAST` -> `CONFIRMING` -> `CONFIRMED`  
Terminal/exception states: `DENIED`, `INVALIDATED_KEY_ROTATION`, `REORGED_DROPPED`, `FAILED`.

### 2.2 `ReconciliationReport`
Contains `generated_at`, `chain_height`, `chain_tip_hash`, `reconciled`, `audit_chain_valid`, per-vault `vault_checks` (`ledger_confirmed_balance`, `onchain_confirmed_balance`, `ledger_reserved_balance`, `sum_pending_reserved_amount`, `balance_delta`, `reserved_delta`, `matched`), `discrepancies`, and deterministic `checksum`.

## 3. Validation Error Taxonomy

| Error Code | Boundary | Trigger Condition |
|---|---|---|
| `ERR_INVALID_SCHEMA` | Domain | Wrong `schema_version`, missing `intent_id`/`vault_id` |
| `ERR_INVALID_ADDRESS` | Domain / Policy | Malformed address, `source == destination`, source mismatch |
| `ERR_INVALID_AMOUNT` | Domain | `amount <= 0` |
| `ERR_INVALID_TIMESTAMP` | Domain | Non-RFC3339 timestamp or `expires_at <= created_at` |
| `ERR_EXPIRED_INTENT` | Domain / Signer | `now > expires_at` |
| `ERR_UNSUPPORTED_NETWORK` | Policy | Mainnet/production or unlisted network |
| `ERR_UNSUPPORTED_ASSET` | Policy | Unsupported asset or unit mismatch |
| `ERR_UNKNOWN_VAULT` / `ERR_VAULT_INACTIVE` | Policy / Ledger | Unconfigured or disabled vault |
| `ERR_DESTINATION_NOT_ALLOWLISTED` | Policy | Destination absent from vault allowlist |
| `ERR_AMOUNT_LIMIT_EXCEEDED` | Policy | Exceeds asset or per-destination single-transfer cap |
| `ERR_DAILY_LIMIT_EXCEEDED` | Policy | Would exceed UTC daily cumulative limit |
| `ERR_UNAUTHORIZED_REQUESTER` | Policy | Unknown or inactive requester |
| `ERR_UNAUTHORIZED_APPROVER` | Engine / Signer | Approver not in eligible set or unknown public key |
| `ERR_SELF_APPROVAL_FORBIDDEN` | Engine / Signer | Approver equals `requested_by` |
| `ERR_DUPLICATE_APPROVAL` | Ledger / Signer | Same approver signs intent more than once |
| `ERR_INVALID_SIGNATURE` | Engine / Signer | Invalid Ed25519 signature bytes |
| `ERR_INSUFFICIENT_APPROVALS` | Engine / Signer | Valid distinct approvals `< required_approvals` |
| `ERR_INTENT_HASH_MISMATCH` | Engine / Signer | Payload hash differs from approved `IntentHash` (tampering) |
| `ERR_REPLAY_DETECTED` | Ledger / Signer / Chain | Duplicate `intent_id`, consumed `nonce`, or replayed `tx_hash` |
| `ERR_NONCE_MISMATCH` | Ledger | Out-of-sequence future nonce or `nonce == 0` |
| `ERR_INSUFFICIENT_FUNDS` | Ledger / Chain | `available_balance < amount` |
| `ERR_KEY_EPOCH_MISMATCH` | Ledger / Signer | Intent `key_epoch != active_key_epoch` or invalidated by rotation |
| `ERR_SIGNER_OFFLINE` | Signer | Individual signer node unavailable |
| `ERR_SIGNER_QUORUM_UNAVAILABLE` | Signer | Online signer nodes `< signing_threshold` |
| `ERR_MISSING_CONFIG` / `ERR_INVALID_CONFIG` | Policy / Startup | Missing file, bad JSON, or invalid threshold/network bounds |
| `ERR_STORAGE_UNAVAILABLE` | Storage | Unattached PostgreSQL handle or I/O persistence failure |
| `ERR_RECONCILIATION_MISMATCH` | Reconciler | Balance/reservation delta `!= 0` or audit chain broken |

## 4. Fixtures Inventory

- **Valid reference fixture:** `data/fixtures/reference_fixture.json` + independent oracle `data/fixtures/expected_reference_output.json`
- **Invalid & boundary fixtures:** `data/fixtures/invalid_inputs.json` (mainnet, unlisted destination, over-limit amount, zero amount, malformed address, unsupported asset)
- **Resilience & failure scenario catalog:** `data/fixtures/integration_scenarios.json`
