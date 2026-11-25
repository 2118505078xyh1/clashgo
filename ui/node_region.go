package ui

import "clashgo/internal/autogroup"

// nodeRegionLabel 从节点名里推断地区（如「香港 201 | 专线」→「香港」）。
//
// 只做名称匹配，不发网络请求：出口地区探测已经移除，
// 地区信息直接从节点名里取，够用且零成本。
func (a *App) nodeRegionLabel(node string) string {
	if node == "" {
		return ""
	}
	return autogroup.RegionOf(node)
}
