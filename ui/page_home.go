package ui

import (
	"context"
	"fmt"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/ipinfo"
	"clashgo/internal/version"
)

func (a *App) pageHome(c *ui.Context) {
	t := c.Theme()
	ui.Scroll(c).Grow(1).Padding(24).Gap(18).Children(func() {
		// Shared heading with the help button.
		a.pageHeader(c, a.tr("overview"), func() {
			text(c, "v"+version.App).FontSize(10).TextColor(t.TextMuted)
		})

		// 首次使用引导（导入订阅前显示，之后自动消失）
		if !a.Settings.OnboardingDone {
			a.onboardingBanner(c)
		}

		// 所有节点都不可用时的告警（仅提示，不自动改系统代理）
		a.allNodesDownBanner(c)

		// 大状态卡：整卡可点开关系统代理，显示已转发流量（参考移动版设计）
		a.proxyStatusCard(c)

		// 代理模式卡（Clash Verge 首页标准卡片：规则/全局/直连）
		card(c, func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, iconGlobe).FontSize(18).TextColor(t.Accent)
				text(c, "代理模式").FontSize(15).Bold()
			})
			ui.Row(c).Gap(6).Children(func() {
				for _, m := range []struct{ key, label string }{
					{"rule", "规则"}, {"global", "全局"}, {"direct", "直连"},
				} {
					mk := m.key
					sel := a.Settings.Mode == mk
					b := ui.Button(c, m.label).Grow(1).Radius(8)
					if sel {
						b.Background(t.Accent).TextColor(t.AccentText)
					}
					if b.Clicked() {
						a.setMode(mk)
					}
				}
			})
		})

		// 网络设置卡：系统代理 / 虚拟网卡（Clash Verge 首页标准卡片）
		card(c, func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, iconShield).FontSize(18).TextColor(t.Accent)
				text(c, "网络设置").FontSize(15).Bold()
			})
			ui.Row(c).Gap(10).Children(func() {
				ui.Column(c).Gap(2).Children(func() {
					text(c, "系统代理").FontSize(13).Bold()
					text(c, "接管系统 HTTP/SOCKS 流量").FontSize(10).TextColor(t.TextMuted)
				}).Grow(1)
				if ui.Switch(c, &a.Settings.EnableSystemProxy).Changed() {
					a.applySystemProxy()
				}
			})
			ui.Row(c).Gap(10).Children(func() {
				ui.Column(c).Gap(2).Children(func() {
					text(c, "虚拟网卡 (TUN)").FontSize(13).Bold()
					text(c, "接管所有程序流量，需管理员权限").FontSize(10).TextColor(t.TextMuted)
				}).Grow(1)
				if ui.Switch(c, &a.Settings.EnableTUN).Changed() {
					a.mustSaveSettings()
					a.reapplyCore()
				}
			})
		})

		// 状态摘要：用户真正关心的三件事——当前节点、订阅流量、连接数
		ui.Row(c).Gap(14).Children(func() {
			statCard(c, iconProxy, "当前节点", a.currentNodeName(), t.Accent)
			statCard(c, iconProfile, "订阅流量", a.subscriptionUsage(), t.Success)
			statCard(c, iconConnections, "活跃连接", fmt.Sprintf("%d 个", len(a.Connections)), t.Accent)
		})

		// 订阅详情卡：已用 / 剩余 / 总量 / 到期时间（对齐 Clash Verge 的订阅卡）
		a.subscriptionDetailCard(c)

		// Traffic chart.
		card(c, func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				text(c, a.trs("实时流量")).FontSize(16).Bold().Grow(1)
				ui.Row(c).Gap(14).Children(func() {
					ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
						ui.Box(c).Size(8, 8).Radius(4).Background(t.Accent)
						text(c, a.trs("下载")).FontSize(11).TextColor(t.TextMuted)
					})
					ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
						ui.Box(c).Size(8, 8).Radius(4).Background(t.Warning)
						text(c, a.trs("上传")).FontSize(11).TextColor(t.TextMuted)
					})
				})
			})
			ui.Box(c).Height(130).FillWidth().Radius(8).Draw(func(p *ui.Painter, r ui.Rect) {
				drawTrafficChart(p, r, a.upHistory, a.downHistory, t)
			})
		})

		// Rate cards.
		ui.Row(c).Gap(14).Children(func() {
			rateCard(c, "↓", "下载", humanRate(a.DownRate), humanBytes(a.Down), t.Accent)
			rateCard(c, "↑", "上传", humanRate(a.UpRate), humanBytes(a.Up), t.Warning)
			rateCard(c, "", "活跃连接", fmt.Sprintf("%d", len(a.Connections)), "实时", t.Success)
		})

		// 代理组概览：所有组的当前选择。
		card(c, func() {
			sectionTitle(c, "代理组", "各组当前选择")
			count := 0
			for _, name := range a.groupNames() {
				p := a.Proxies[name]
				if count >= 6 {
					break
				}
				count++
				ui.Row(c).Gap(10).Padding(8, 0).Children(func() {
					ui.Box(c).Size(6, 6).Radius(3).Background(t.Success)
					text(c, name).Grow(1).FontSize(13)
					text(c, p.Now).TextColor(t.Accent).FontSize(13)
				})
			}
			if count == 0 {
				text(c, "暂无代理组数据，导入订阅后即可看到节点").TextColor(t.TextMuted)
			}
		})

		// Exit IP info.
		card(c, func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				sectionTitle(c, "出口 IP", "经代理探测")
				ui.Spacer(c).Grow(1)
				if ui.Button(c, a.trs("刷新")).Clicked() {
					a.refreshExitIP()
				}
			})
			if a.ExitIP != nil {
				ui.Row(c).Gap(24).Padding(4, 0).Children(func() {
					ui.Column(c).Gap(2).Children(func() {
						text(c, "IP 地址").FontSize(11).TextColor(t.TextMuted)
						text(c, a.ExitIP.IP).FontSize(14).Bold()
					}).Grow(1)
					ui.Column(c).Gap(2).Children(func() {
						text(c, "地区").FontSize(11).TextColor(t.TextMuted)
						text(c, a.ExitIP.Country+" "+a.ExitIP.City).FontSize(14)
					}).Grow(1)
					ui.Column(c).Gap(2).Children(func() {
						text(c, "运营商").FontSize(11).TextColor(t.TextMuted)
						text(c, a.ExitIP.ISP).FontSize(12)
					}).Grow(1)
				})
			} else {
				text(c, "点击「刷新」探测当前出口 IP").TextColor(t.TextMuted).FontSize(12)
			}
		})
	})
}

func (a *App) refreshExitIP() {
	port := a.Settings.MixedPort
	if a.EffectivePort > 0 {
		port = a.EffectivePort
	}
	go func() {
		info, err := ipinfo.New(port).Probe(context.Background())
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
