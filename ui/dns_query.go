package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// queryDNS performs an active DNS query through 自研内核 and stores a
// human-readable result in the app state.
func (a *App) queryDNS() {
	name := strings.TrimSpace(a.DNSQueryName)
	if name == "" {
		return
	}
	go func() {
		base := a.currentClient().Base
		req, err := http.NewRequest(http.MethodGet,
			base+"/dns/query?name="+url.QueryEscape(name)+"&type=A", nil)
		if err != nil {
			a.win.Update(func() { a.DNSQueryResult = "请求失败: " + err.Error() })
			return
		}
		if a.Settings.Secret != "" {
			req.Header.Set("Authorization", "Bearer "+a.Settings.Secret)
		}
		resp, err := a.currentClient().HTTP.Do(req)
		if err != nil {
			a.win.Update(func() { a.DNSQueryResult = "查询失败: " + err.Error() })
			return
		}
		defer resp.Body.Close()
		var raw struct {
			Status int `json:"Status"`
			Answer []struct {
				Data string `json:"data"`
			} `json:"Answer"`
			Question []struct {
				Name string `json:"name"`
			} `json:"Question"`
		}
		var result string
		if json.NewDecoder(resp.Body).Decode(&raw) != nil {
			result = "解析响应失败"
		} else if len(raw.Answer) == 0 {
			result = fmt.Sprintf("无 A 记录 (Status=%d)", raw.Status)
		} else {
			var ips []string
			for _, ans := range raw.Answer {
				ips = append(ips, ans.Data)
			}
			result = strings.Join(ips, ", ")
		}
		a.win.Update(func() { a.DNSQueryResult = result })
	}()
}
