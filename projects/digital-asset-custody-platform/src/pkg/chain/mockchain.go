package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/financial-security/digital-asset-custody-platform/src/pkg/domain"
)

// BundleVerifier verifies cryptographic multisig signatures before the mock chain accepts a broadcast.
type BundleVerifier interface {
	VerifyBundle(intent domain.TransferIntent, bundle domain.MultisigBundle) error
}

// ChainSnapshot captures serializable mock testnet state for restart/rerun tests.
type ChainSnapshot struct {
	ConfirmationDepth int                                `json:"confirmation_depth"`
	ForkCounter       int                                `json:"fork_counter"`
	Blocks            []domain.Block                     `json:"blocks"`
	Mempool           []string                           `json:"mempool"`
	Transactions      map[string]domain.ChainTransaction `json:"transactions"`
	Balances          map[string]int64                   `json:"balances"` // network|addr|asset -> balance
}

// MockChain is a deterministic offline testnet simulator supporting block mining,
// confirmation depth tracking, on-chain balances, and simulated chain reorganizations.
type MockChain struct {
	mu                sync.RWMutex
	confirmationDepth int
	forkCounter       int
	blocks            []domain.Block
	mempool           []string
	txs               map[string]domain.ChainTransaction
	balances          map[string]int64
}

func NewMockChain(confirmationDepth int, genesisTime time.Time) *MockChain {
	if confirmationDepth < 1 {
		confirmationDepth = 2
	}
	genesis := domain.Block{
		Height:     0,
		ParentHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
		ForkTag:    "canonical-0",
		Timestamp:  genesisTime.UTC().Format(time.RFC3339),
		TxHashes:   []string{},
	}
	genesis.Hash = computeBlockHash(genesis)
	return &MockChain{
		confirmationDepth: confirmationDepth,
		blocks:            []domain.Block{genesis},
		mempool:           make([]string, 0),
		txs:               make(map[string]domain.ChainTransaction),
		balances:          make(map[string]int64),
	}
}

func addrBalKey(network, address, asset string) string {
	return strings.ToLower(network) + "|" + strings.ToLower(address) + "|" + strings.ToUpper(asset)
}

// CreditAddress simulates an incoming testnet deposit or faucet funding to an address.
func (c *MockChain) CreditAddress(network, address, asset string, amount int64) error {
	if amount <= 0 {
		return domain.NewError(domain.ErrInvalidAmount, "credit amount must be positive")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.balances[addrBalKey(network, address, asset)] += amount
	return nil
}

// GetBalance returns the current canonical on-chain balance for an address and asset.
func (c *MockChain) GetBalance(network, address, asset string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.balances[addrBalKey(network, address, asset)]
}

// Tip returns the current canonical head block.
func (c *MockChain) Tip() domain.Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.blocks[len(c.blocks)-1]
}

// Broadcast validates multisig signatures and queues a signed transaction in the mock mempool.
func (c *MockChain) Broadcast(intent domain.TransferIntent, bundle domain.MultisigBundle, verifier BundleVerifier) (domain.ChainTransaction, error) {
	if verifier != nil {
		if err := verifier.VerifyBundle(intent, bundle); err != nil {
			return domain.ChainTransaction{}, err
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.txs[bundle.TxHash]; exists {
		return domain.ChainTransaction{}, domain.NewError(domain.ErrReplayDetected, "transaction hash already broadcast: "+bundle.TxHash)
	}
	for _, existing := range c.txs {
		if existing.Status != domain.ChainTxOrphaned && existing.VaultID == intent.VaultID && existing.Nonce == intent.Nonce {
			return domain.ChainTransaction{}, domain.NewError(domain.ErrReplayDetected,
				fmt.Sprintf("on-chain replay detected for vault %s nonce %d", intent.VaultID, intent.Nonce))
		}
	}

	srcKey := addrBalKey(intent.Network, intent.SourceAddress, intent.Asset)
	if c.balances[srcKey] < intent.Amount {
		return domain.ChainTransaction{}, domain.NewError(domain.ErrInsufficientFunds, "insufficient on-chain balance for broadcast")
	}

	tx := domain.ChainTransaction{
		TxHash:             bundle.TxHash,
		IntentID:           intent.IntentID,
		IntentHash:         bundle.IntentHash,
		VaultID:            intent.VaultID,
		Network:            intent.Network,
		Asset:              intent.Asset,
		Amount:             intent.Amount,
		SourceAddress:      strings.ToLower(intent.SourceAddress),
		DestinationAddress: strings.ToLower(intent.DestinationAddress),
		Nonce:              intent.Nonce,
		KeyEpoch:           intent.KeyEpoch,
		Bundle:             bundle,
		Status:             domain.ChainTxMempool,
		Confirmations:      0,
	}
	c.txs[tx.TxHash] = tx
	c.mempool = append(c.mempool, tx.TxHash)
	return tx, nil
}

// MineBlock mines a single deterministic block containing all currently queued mempool transactions.
func (c *MockChain) MineBlock(now time.Time) domain.Block {
	c.mu.Lock()
	defer c.mu.Unlock()

	parent := c.blocks[len(c.blocks)-1]
	txHashes := append([]string(nil), c.mempool...)
	sort.Strings(txHashes)
	c.mempool = make([]string, 0)

	blk := domain.Block{
		Height:     parent.Height + 1,
		ParentHash: parent.Hash,
		ForkTag:    fmt.Sprintf("canonical-%d", c.forkCounter),
		Timestamp:  now.UTC().Format(time.RFC3339),
		TxHashes:   txHashes,
	}
	blk.Hash = computeBlockHash(blk)
	c.blocks = append(c.blocks, blk)

	// Apply balance transitions for newly included transactions.
	for _, h := range txHashes {
		tx := c.txs[h]
		srcKey := addrBalKey(tx.Network, tx.SourceAddress, tx.Asset)
		dstKey := addrBalKey(tx.Network, tx.DestinationAddress, tx.Asset)
		if c.balances[srcKey] >= tx.Amount {
			c.balances[srcKey] -= tx.Amount
			c.balances[dstKey] += tx.Amount
			tx.BlockHeight = blk.Height
			tx.BlockHash = blk.Hash
			tx.Confirmations = 1
			if tx.Confirmations >= c.confirmationDepth {
				tx.Status = domain.ChainTxConfirmed
			} else {
				tx.Status = domain.ChainTxIncluded
			}
			c.txs[h] = tx
		} else {
			tx.Status = domain.ChainTxOrphaned
			c.txs[h] = tx
		}
	}

	// Advance confirmations for all previously included transactions on the canonical chain.
	c.refreshConfirmationsLocked(blk.Height)
	return blk
}

// TriggerReorg simulates a chain reorganization of the specified depth.
// Transactions in orphaned blocks are reversed on-chain; those in dropTxHashes become ORPHANED,
// while remaining transactions are requeued into mempool so subsequent blocks can re-include them on the new fork.
func (c *MockChain) TriggerReorg(depth int, dropTxHashes []string, now time.Time) (domain.ReorgResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if depth < 1 || depth >= len(c.blocks) {
		return domain.ReorgResult{}, domain.NewError(domain.ErrInvalidSchema,
			fmt.Sprintf("invalid reorg depth %d for chain height %d", depth, len(c.blocks)-1))
	}

	dropSet := make(map[string]bool, len(dropTxHashes))
	for _, h := range dropTxHashes {
		dropSet[h] = true
	}

	cutIndex := len(c.blocks) - depth
	orphaned := append([]domain.Block(nil), c.blocks[cutIndex:]...)
	c.blocks = c.blocks[:cutIndex]
	ancestor := c.blocks[len(c.blocks)-1]

	orphanedHashes := make([]string, 0, len(orphaned))
	requeued := make([]string, 0)
	dropped := make([]string, 0)

	// Reverse balance effects from newest orphaned block back to oldest.
	for i := len(orphaned) - 1; i >= 0; i-- {
		blk := orphaned[i]
		orphanedHashes = append(orphanedHashes, blk.Hash)
		for _, txHash := range blk.TxHashes {
			tx, ok := c.txs[txHash]
			if !ok {
				continue
			}
			if tx.Status == domain.ChainTxIncluded || tx.Status == domain.ChainTxConfirmed {
				srcKey := addrBalKey(tx.Network, tx.SourceAddress, tx.Asset)
				dstKey := addrBalKey(tx.Network, tx.DestinationAddress, tx.Asset)
				c.balances[dstKey] -= tx.Amount
				c.balances[srcKey] += tx.Amount
			}
			tx.BlockHeight = 0
			tx.BlockHash = ""
			tx.Confirmations = 0
			if dropSet[txHash] {
				tx.Status = domain.ChainTxOrphaned
				dropped = append(dropped, txHash)
			} else {
				tx.Status = domain.ChainTxMempool
				c.mempool = append(c.mempool, txHash)
				requeued = append(requeued, txHash)
			}
			c.txs[txHash] = tx
		}
	}

	// Build a competing fork of equal depth (initially empty blocks) so chain tip changes deterministically.
	c.forkCounter++
	for i := 0; i < depth; i++ {
		parent := c.blocks[len(c.blocks)-1]
		forkBlk := domain.Block{
			Height:     parent.Height + 1,
			ParentHash: parent.Hash,
			ForkTag:    fmt.Sprintf("reorg-fork-%d", c.forkCounter),
			Timestamp:  now.UTC().Add(time.Duration(i+1) * time.Second).Format(time.RFC3339),
			TxHashes:   []string{},
		}
		forkBlk.Hash = computeBlockHash(forkBlk)
		c.blocks = append(c.blocks, forkBlk)
	}

	c.refreshConfirmationsLocked(c.blocks[len(c.blocks)-1].Height)
	sort.Strings(requeued)
	sort.Strings(dropped)

	return domain.ReorgResult{
		ReorgDepth:       depth,
		CommonAncestor:   ancestor.Height,
		OrphanedBlocks:   orphanedHashes,
		NewCanonicalTip:  c.blocks[len(c.blocks)-1].Hash,
		RequeuedTxHashes: requeued,
		DroppedTxHashes:  dropped,
	}, nil
}

// GetTxReceipt returns the current on-chain status of a transaction hash.
func (c *MockChain) GetTxReceipt(txHash string) (domain.ChainTransaction, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	tx, ok := c.txs[txHash]
	return tx, ok
}

// Snapshot exports mock chain state for durable persistence and restart testing.
func (c *MockChain) Snapshot() ChainSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snap := ChainSnapshot{
		ConfirmationDepth: c.confirmationDepth,
		ForkCounter:       c.forkCounter,
		Blocks:            append([]domain.Block(nil), c.blocks...),
		Mempool:           append([]string(nil), c.mempool...),
		Transactions:      make(map[string]domain.ChainTransaction, len(c.txs)),
		Balances:          make(map[string]int64, len(c.balances)),
	}
	for k, v := range c.txs {
		snap.Transactions[k] = v
	}
	for k, v := range c.balances {
		snap.Balances[k] = v
	}
	return snap
}

// Restore reloads mock chain state from a persisted snapshot.
func (c *MockChain) Restore(snap ChainSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.confirmationDepth = snap.ConfirmationDepth
	c.forkCounter = snap.ForkCounter
	c.blocks = append([]domain.Block(nil), snap.Blocks...)
	c.mempool = append([]string(nil), snap.Mempool...)
	c.txs = snap.Transactions
	c.balances = snap.Balances
}

func (c *MockChain) refreshConfirmationsLocked(tipHeight uint64) {
	for h, tx := range c.txs {
		if tx.Status == domain.ChainTxIncluded || tx.Status == domain.ChainTxConfirmed {
			if tx.BlockHeight > 0 && tipHeight >= tx.BlockHeight {
				tx.Confirmations = int(tipHeight-tx.BlockHeight) + 1
				if tx.Confirmations >= c.confirmationDepth {
					tx.Status = domain.ChainTxConfirmed
				} else {
					tx.Status = domain.ChainTxIncluded
				}
				c.txs[h] = tx
			}
		}
	}
}

func computeBlockHash(b domain.Block) string {
	h := sha256.New()
	h.Write([]byte("MOCK_CHAIN_BLOCK_V1:"))
	h.Write([]byte(fmt.Sprintf("%d|%s|%s|%s|", b.Height, b.ParentHash, b.ForkTag, b.Timestamp)))
	for _, tx := range b.TxHashes {
		h.Write([]byte(tx + ","))
	}
	return "0x" + hex.EncodeToString(h.Sum(nil))
}
