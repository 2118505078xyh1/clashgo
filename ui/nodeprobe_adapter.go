package ui

// SelectNode lets the node prober switch nodes (nodeprobe.Selector interface).
func (a *App) SelectNode(group, name string) error {
	return a.currentClient().SelectNode(group, name)
}
