package domain

import (
	"errors"
	"fmt"
)

// ErrorCode defines stable machine-readable error identifiers across all custody boundaries.
type ErrorCode string

const (
	ErrInvalidSchema             ErrorCode = "ERR_INVALID_SCHEMA"
	ErrInvalidAddress            ErrorCode = "ERR_INVALID_ADDRESS"
	ErrInvalidAmount             ErrorCode = "ERR_INVALID_AMOUNT"
	ErrInvalidTimestamp          ErrorCode = "ERR_INVALID_TIMESTAMP"
	ErrExpiredIntent             ErrorCode = "ERR_EXPIRED_INTENT"
	ErrUnsupportedNetwork        ErrorCode = "ERR_UNSUPPORTED_NETWORK"
	ErrUnsupportedAsset          ErrorCode = "ERR_UNSUPPORTED_ASSET"
	ErrUnknownVault              ErrorCode = "ERR_UNKNOWN_VAULT"
	ErrVaultInactive             ErrorCode = "ERR_VAULT_INACTIVE"
	ErrDestinationNotAllowlisted ErrorCode = "ERR_DESTINATION_NOT_ALLOWLISTED"
	ErrAmountLimitExceeded       ErrorCode = "ERR_AMOUNT_LIMIT_EXCEEDED"
	ErrDailyLimitExceeded        ErrorCode = "ERR_DAILY_LIMIT_EXCEEDED"
	ErrUnauthorizedRequester     ErrorCode = "ERR_UNAUTHORIZED_REQUESTER"
	ErrUnauthorizedApprover      ErrorCode = "ERR_UNAUTHORIZED_APPROVER"
	ErrSelfApprovalForbidden     ErrorCode = "ERR_SELF_APPROVAL_FORBIDDEN"
	ErrDuplicateApproval         ErrorCode = "ERR_DUPLICATE_APPROVAL"
	ErrInvalidSignature          ErrorCode = "ERR_INVALID_SIGNATURE"
	ErrInsufficientApprovals     ErrorCode = "ERR_INSUFFICIENT_APPROVALS"
	ErrIntentHashMismatch        ErrorCode = "ERR_INTENT_HASH_MISMATCH"
	ErrReplayDetected            ErrorCode = "ERR_REPLAY_DETECTED"
	ErrNonceMismatch             ErrorCode = "ERR_NONCE_MISMATCH"
	ErrInsufficientFunds         ErrorCode = "ERR_INSUFFICIENT_FUNDS"
	ErrKeyEpochMismatch          ErrorCode = "ERR_KEY_EPOCH_MISMATCH"
	ErrSignerOffline             ErrorCode = "ERR_SIGNER_OFFLINE"
	ErrSignerQuorumUnavailable   ErrorCode = "ERR_SIGNER_QUORUM_UNAVAILABLE"
	ErrInvalidStateTransition    ErrorCode = "ERR_INVALID_STATE_TRANSITION"
	ErrMissingConfig             ErrorCode = "ERR_MISSING_CONFIG"
	ErrInvalidConfig             ErrorCode = "ERR_INVALID_CONFIG"
	ErrReconciliationMismatch    ErrorCode = "ERR_RECONCILIATION_MISMATCH"
	ErrStorageUnavailable        ErrorCode = "ERR_STORAGE_UNAVAILABLE"
	ErrIntentNotFound            ErrorCode = "ERR_INTENT_NOT_FOUND"
	ErrPolicyDenied              ErrorCode = "ERR_POLICY_DENIED"
)

// CustodyError carries a stable ErrorCode and human-readable message without exposing secrets.
type CustodyError struct {
	Code    ErrorCode      `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
	Cause   error          `json:"-"`
}

func (e *CustodyError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *CustodyError) Unwrap() error {
	return e.Cause
}

// NewError creates a typed CustodyError.
func NewError(code ErrorCode, msg string) *CustodyError {
	return &CustodyError{Code: code, Message: msg}
}

// WrapError wraps an underlying error with a typed CustodyError.
func WrapError(code ErrorCode, msg string, cause error) *CustodyError {
	return &CustodyError{Code: code, Message: msg, Cause: cause}
}

// WithDetails attaches non-sensitive structured metadata to a CustodyError.
func (e *CustodyError) WithDetails(details map[string]any) *CustodyError {
	e.Details = details
	return e
}

// CodeOf extracts the ErrorCode from an error, or empty string if not a CustodyError.
func CodeOf(err error) ErrorCode {
	if err == nil {
		return ""
	}
	var ce *CustodyError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}
