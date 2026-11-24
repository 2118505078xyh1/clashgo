package ui

import (
	"context"
	"time"

	"clashgo/internal/nodeprobe"
	"clashgo/internal/paths"
)

// probeNodeIPs probes the exit IP of every node in a group, with caching and
// automatic restoration of the user's selected node.
func (a *App) probeNodeIPs(group string, nodes []string, original string) {
	if a.NodeProbeBusy || len(nodes) == 0 {
		return
	}
	a.NodeProbeBusy = true
	store := nodeprobe.NewStore(paths.Home)
	probe := nodeprobe.New(a, a.Settings.MixedPort, store, func(r nodeprobe.Result) {
		a.win.Update(func() {
			a.NodeIPResults[r.Node] = r
		})
	})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		probe.ProbeGroup(ctx, group, original, nodes)
		a.win.Update(func() { a.NodeProbeBusy = false })
	}()
}

// nodeRegionLabel returns a short region label for a probed node.
func (a *App) nodeRegionLabel(node string) string {
	r, ok := a.NodeIPResults[node]
	if !ok || !r.OK {
		return ""
	}
	if r.CountryCode != "" && r.CountryCode != "unknown" {
		return r.CountryCode
	}
	return r.Country
}
