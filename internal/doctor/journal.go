package doctor

import (
	"context"
	"time"

	"github.com/sSOFTINn/ProjectAuditOrchestrator/internal/installation"
)

// Read status and IDs from one validated journal snapshot under the same
// shared lease. A failed read returns no partial IDs and never creates state.
func pendingRunIDs(ctx context.Context, root string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store, err := installation.Open(root)
	if err != nil {
		return nil, err
	}
	lockCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	lease, err := store.Lock(lockCtx, false)
	if err != nil {
		return nil, err
	}
	defer lease.Close()
	pending, err := store.Pending()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(pending))
	for _, run := range pending {
		ids = append(ids, run.ID)
	}
	return ids, nil
}
