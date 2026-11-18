package XRay

import (
	"context"
	"strconv"
	"strings"
	"sync"

	"github.com/xtls/xray-core/core"
)

type configureBalancerDiagnostics func(context.Context, *core.Config) (context.Context, *balancerDiagnostics)

func prepareBalancerDiagnostics(ctx context.Context, config *core.Config, configure configureBalancerDiagnostics) (context.Context, *balancerDiagnostics) {
	if configure == nil {
		return ctx, nil
	}
	return configure(ctx, config)
}

type balancerSelection struct {
	sequence uint64
	group    int
	node     int
}

// Only numeric aliases and the local sequence are ever retained in history.
type balancerDiagnostics struct {
	mu       sync.Mutex
	rows     []balancerSelection
	sequence uint64
}

func (d *balancerDiagnostics) record(group, node int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.rows) == 0 {
		return
	}
	d.rows[d.sequence%uint64(len(d.rows))] = balancerSelection{d.sequence + 1, group, node}
	d.sequence++
}

func (d *balancerDiagnostics) disable() {
	d.mu.Lock()
	defer d.mu.Unlock()
	clear(d.rows)
	d.rows = nil
	d.sequence = 0
}

func (d *balancerDiagnostics) snapshot() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var output strings.Builder
	capacity := uint64(len(d.rows))
	for index := d.sequence - min(d.sequence, capacity); index < d.sequence; index++ {
		row := d.rows[index%capacity]
		output.WriteString(strconv.FormatUint(row.sequence, 10))
		output.WriteByte(',')
		output.WriteString(strconv.Itoa(row.group))
		output.WriteByte(',')
		output.WriteString(strconv.Itoa(row.node))
		output.WriteByte('\n')
	}
	return output.String()
}
