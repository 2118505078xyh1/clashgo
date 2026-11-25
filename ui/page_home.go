package ui

import (
	"context"
	"strings"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/ipinfo"
)

func (a *App) pageHome(c *ui.Context) {
	ui.Scroll(c).Grow(1).Padding(spaceLg).Gap(spaceMd).Children(func() {
		// 首次使用引导（导入订阅前显示，之后自动消失）
		if !a.Settings.OnboardingDone {
			a.onboardingBanner(c)
		}

		// 所有节点都不可用时的告警（仅提示，不自动改系统代理）
		a.allNodesDownBanner(c)

		// 1) 大状态卡与虚拟网卡开关并排（3:2），两张卡等高。
		ui.Row(c).Gap(spaceMd).AlignItems(ui.Stretch).Children(func() {
			ui.Column(c).Grow(3).Children(func() {
				a.proxyStatusCard(c)
			})
			ui.Column(c).Grow(2).Children(func() {
				a.networkCard(c)
			})
		})

		// 3) 代理模式：规则 / 全局 / 直连
		a.modeCard(c)

		// 4) 实时流量
		a.trafficCard(c)

		// 5) 出口 IP
		a.exitIPCard(c)
	})
}

// trafficCard 是首页的实时流量图。
func (a *App) trafficCard(c *ui.Context) {
	t := c.Theme()
	card(c, func() {
		ui.Row(c).AlignItems(ui.Center).Children(func() {
			text(c, a.trs("实时流量")).FontSize(14).Bold().Grow(1)
			ui.Row(c).Gap(spaceMd).Children(func() {
				ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
					ui.Box(c).Size(8, 8).Radius(4).Background(ui.Hex(brandPrimary))
					text(c, a.trs("下载")).FontSize(11).TextColor(ui.Hex(textTertiary))
				})
				ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
					ui.Box(c).Size(8, 8).Radius(4).Background(ui.Hex(colorWarning))
					text(c, a.trs("上传")).FontSize(11).TextColor(ui.Hex(textTertiary))
				})
			})
		})
		ui.Box(c).Height(150).FillWidth().Radius(radiusMd).Draw(func(p *ui.Painter, r ui.Rect) {
			drawTrafficChart(p, r, a.upHistory, a.downHistory, t)
		})
		// 当前速率
		ui.Row(c).Gap(spaceMd).Children(func() {
			ui.Row(c).Gap(spaceSm).AlignItems(ui.Center).Grow(1).Children(func() {
				text(c, "↓").FontSize(13).Bold().TextColor(ui.Hex(brandPrimary))
				text(c, humanRate(a.DownRate)).FontSize(14).Bold().TextColor(ui.Hex(brandPrimary))
			})
			ui.Row(c).Gap(spaceSm).AlignItems(ui.Center).Grow(1).Children(func() {
				text(c, "↑").FontSize(13).Bold().TextColor(ui.Hex(colorWarning))
				text(c, humanRate(a.UpRate)).FontSize(14).Bold().TextColor(ui.Hex(colorWarning))
			})
			text(c, "累计 "+humanBytes(a.Down+a.Up)).FontSize(11).TextColor(ui.Hex(textTertiary))
		})
	})
}

// exitIPCard 显示当前出口 IP 与地区。
//
// 做成一行：标题 + 地区徽标 + 刷新按钮在同一行，
// 探测结果直接跟在后面，不再占一整块竖向空间。
func (a *App) exitIPCard(c *ui.Context) {
	card(c, func() {
		ui.Row(c).Gap(spaceMd).AlignItems(ui.Center).Children(func() {
			text(c, "出口 IP").FontSize(14).Bold()
			// 当前节点对应的地区：从节点名推断，不需要额外探测。
			if region := a.nodeRegionLabel(a.currentNodeName()); region != "" {
				badge(c, region, ui.Hex(brandPrimary), withAlpha(ui.Hex(brandPrimary), 0.15))
			}
			if a.ExitIP != nil {
				// 结果与标题同行：IP / 地区 / 运营商 用竖线分隔。
				ui.Row(c).Gap(spaceSm).AlignItems(ui.Baseline).Grow(1).Children(func() {
					text(c, a.ExitIP.IP).FontSize(13).Bold().TextColor(ui.Hex(brandPrimary))
					if loc := strings.TrimSpace(a.ExitIP.Country + " " + a.ExitIP.City); loc != "" {
						text(c, "|").FontSize(12).TextColor(ui.Hex(textTertiary))
						text(c, loc).FontSize(12).TextColor(c.Theme().Text)
					}
					if isp := strings.TrimSpace(a.ExitIP.ISP); isp != "" {
						text(c, "|").FontSize(12).TextColor(ui.Hex(textTertiary))
						text(c, isp).FontSize(12).TextColor(ui.Hex(textTertiary))
					}
				})
			} else {
				text(c, "点击右侧刷新探测").FontSize(12).TextColor(ui.Hex(textTertiary)).Grow(1)
			}
			pillButton(c, "刷新", "重新探测出口 IP", func() { a.refreshExitIP() })
		})
	})
}

func (a *App) refreshExitIP() {
	port := a.Settings.MixedPort
	if a.EffectivePort > 0 {
		port = a.EffectivePort
	}
	go func() {
		// 系统代理开着就探测代理出口，关着就探测直连出口。
		// 一直走代理探测的话，代理关了界面还显示香港节点，
		// 用户会以为开关没生效。
		var prober *ipinfo.Prober
		if a.Settings.EnableSystemProxy {
			prober = ipinfo.New(port)
		} else {
			prober = ipinfo.NewDirect()
		}
		info, err := prober.Probe(context.Background())
		if err != nil {
			logf("exit ip: %v", err)
			return
		}
		a.win.Update(func() { a.ExitIP = info })
	}()
}

func statCard(c *ui.Context, icon *ui.SVG, label, value string, accent ui.Color) ui.Element {
	return card(c, func() {
		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			ui.Box(c).Size(38, 38).Radius(10).Center().
				Background(withAlpha(accent, 0.12)).
				Children(func() { ui.Icon(c, icon).FontSize(20).TextColor(accent) })
			ui.Column(c).Gap(3).Children(func() {
				text(c, label).FontSize(11).TextColor(c.Theme().TextMuted)
				text(c, value).FontSize(15).Bold()
			})
		})
	}).Grow(1)
}

func rateCard(c *ui.Context, glyph, label, value, sub string, accent ui.Color) ui.Element {
	return card(c, func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			if glyph != "" {
				text(c, glyph).FontSize(20).TextColor(accent).Width(20).Center()
			}
			ui.Column(c).Gap(2).Children(func() {
				text(c, label).FontSize(11).TextColor(c.Theme().TextMuted)
				text(c, value).FontSize(19).Bold()
				text(c, sub).FontSize(10).TextColor(c.Theme().TextMuted)
			})
		})
	}).Grow(1)
}

// subscriptionDetailCard 显示当前订阅的已用/剩余/总量/到期时间。
func (a *App) subscriptionDetailCard(c *ui.Context) {
	t := c.Theme()
	info := a.subscriptionTraffic()
	item := a.Profiles.DB.CurrentItem()
	name := "未选择订阅"
	if item != nil {
		name = item.Name
	}
	card(c, func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Box(c).Size(38, 38).Radius(10).Center().
				Background(withAlpha(t.Success, 0.12)).
				Children(func() { ui.Icon(c, iconProfile).FontSize(20).TextColor(t.Success) })
			ui.Column(c).Gap(2).Children(func() {
				text(c, name).FontSize(14).Bold()
				text(c, "订阅流量详情").FontSize(10).TextColor(t.TextMuted)
			}).Grow(1)
		})
		if !info.Available {
			text(c, "订阅未返回流量信息（刷新订阅后可显示）").FontSize(12).TextColor(t.TextMuted).Padding(8, 0)
			return
		}
		if info.Total != "" {
			ui.Row(c).Gap(24).Padding(8, 0).Children(func() {
				ui.Column(c).Gap(2).Children(func() {
					text(c, "已用").FontSize(10).TextColor(t.TextMuted)
					text(c, info.Used).FontSize(14).Bold().TextColor(t.Warning)
				}).Grow(1)
				ui.Column(c).Gap(2).Children(func() {
					text(c, "剩余").FontSize(10).TextColor(t.TextMuted)
					text(c, info.Remaining).FontSize(14).Bold().TextColor(t.Success)
				}).Grow(1)
				ui.Column(c).Gap(2).Children(func() {
					text(c, "总量").FontSize(10).TextColor(t.TextMuted)
					text(c, info.Total).FontSize(14).Bold()
				}).Grow(1)
			})
			ui.Box(c).FillWidth().Height(6).Radius(3).Background(withAlpha(t.Accent, 0.18)).Children(func() {
				ui.Box(c).WidthPercent(info.Pct * 100).FillHeight().Radius(3).Background(t.Accent)
			})
		}
		if info.Expire != "" {
			ui.Row(c).Gap(8).Padding(6, 0).Children(func() {
				text(c, "到期时间").FontSize(10).TextColor(t.TextMuted)
				text(c, info.Expire).FontSize(12).Bold()
			})
		}
	})
}

func toggleRow(c *ui.Context, label string, value *bool, onChange func()) {
	ui.Row(c).Gap(10).Children(func() {
		text(c, label).FontSize(13).Grow(1)
		if ui.Switch(c, value).Changed() {
			onChange()
		}
	}).Grow(1)
}

func profileName(a *App) string {
	if item := a.Profiles.DB.CurrentItem(); item != nil {
		return item.Name
	}
	return "无"
}

func (a *App) groupNames() []string {
	var names []string
	for name, p := range a.Proxies {
		if p.Group {
			names = append(names, name)
		}
	}
	sortStrings(names)
	return names
}
