package store

import (
	"context"
	"fmt"
	"time"

	"github.com/financial-security/agent-identity-and-authorization-platform/src/config"
	"github.com/financial-security/agent-identity-and-authorization-platform/src/domain"
)

// Tx defines all state operations executed atomically inside a serialized transaction.
type Tx interface {
	UpsertPrincipal(ctx context.Context, p domain.Principal) error
	GetPrincipal(ctx context.Context, principalID string) (*domain.Principal, error)

	InsertGrant(ctx context.Context, g domain.DelegationGrant) error
	GetGrant(ctx context.Context, grantID string) (*domain.DelegationGrant, error)
	GetGrantChain(ctx context.Context, grantID string) ([]domain.DelegationGrant, error)
	AddGrantSpend(ctx context.Context, grantIDs []string, deltaMinor int64) error

	InsertRevocation(ctx context.Context, r domain.RevocationRecord) error
	IsRevoked(ctx context.Context, targetType domain.RevocationTarget, targetID string) (bool, string, error)

	InsertApproval(ctx context.Context, a domain.ApprovalRecord) error
	GetApproval(ctx context.Context, approvalID string) (*domain.ApprovalRecord, error)
	ConsumeApproval(ctx context.Context, approvalID string, consumedAt time.Time, decisionID string) (bool, error)

	NextSequence(ctx context.Context) (int64, error)
	AppendAuditEvent(ctx context.Context, ev *domain.AuditEvent) error
	ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error)
}

// Store is the persistence boundary supporting ACID transactions and audit retrieval.
type Store interface {
	Close() error
	WithTx(ctx context.Context, fn func(tx Tx) error) error
	ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error)
	GetGrant(ctx context.Context, grantID string) (*domain.DelegationGrant, error)
	GetPrincipal(ctx context.Context, principalID string) (*domain.Principal, error)
}

// Open instantiates the configured storage adapter (sqlite default or postgres).
func Open(ctx context.Context, cfg config.StorageConfig) (Store, error) {
	switch cfg.Driver {
	case "sqlite":
		return NewSQLiteStore(ctx, cfg.DSN)
	case "postgres":
		return NewPostgresStore(ctx, cfg.DSN)
	default:
		return nil, fmt.Errorf("%w: unsupported storage driver %q", config.ErrInvalidConfig, cfg.Driver)
	}
}
