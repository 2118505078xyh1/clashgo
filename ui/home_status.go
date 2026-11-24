package ui

import (
	"fmt"
	"time"
)

// currentNodeName 返回当前代理组选中的节点名（用户最关心的状态）。
func (a *App) currentNodeName() string {
	// GLOBAL/PROXY 组通常保存用户选择。
	for _, name := range []string{"PROXY", "GLOBAL"} {
		if p, ok := a.Proxies[name]; ok && p.Now != "" && p.Now != name {
			return p.Now
		}
	}
	// 退而求其次：任意组里有选中的节点。
	for _, p := range a.Proxies {
		if p.Group && p.Now != "" {
			return p.Now
		}
	}
	return "未选择"
}

// trafficInfo 是当前订阅的流量与到期信息。
type trafficInfo struct {
	Available bool    // 是否有有效数据
	Used      string  // 已用（上行+下行）
	Remaining string  // 剩余
	Total     string  // 总量
	Expire    string  // 到期时间
	Pct       float32 // 已用百分比 0..1
}

// subscriptionTraffic 返回当前订阅的已用/剩余/到期信息。
func (a *App) subscriptionTraffic() trafficInfo {
	item := a.Profiles.DB.CurrentItem()
	if item == nil || item.Extra == nil {
		return trafficInfo{}
	}
	e := item.Extra
	used := e.Download + e.Upload
	info := trafficInfo{Used: humanBytes(used)}
	if e.Total > 0 {
		remain := e.Total - used
		if remain < 0 {
			remain = 0
		}
		info.Available = true
		info.Remaining = humanBytes(remain)
		info.Total = humanBytes(e.Total)
		info.Pct = float32(used) / float32(e.Total)
		if info.Pct < 0 {
			info.Pct = 0
		}
		if info.Pct > 1 {
			info.Pct = 1
		}
	}
	if e.Expire > 0 {
		info.Available = true
		info.Expire = time.Unix(e.Expire, 0).Format("2006-01-02")
	}
	return info
}

// subscriptionUsage 返回当前订阅的流量使用情况摘要（保留给 statCard 用）。
func (a *App) subscriptionUsage() string {
	info := a.subscriptionTraffic()
	if !info.Available || info.Total == "" {
		return "未获取"
	}
	return fmt.Sprintf("%s / %s (%.0f%%)", info.Used, info.Total, info.Pct*100)
}
