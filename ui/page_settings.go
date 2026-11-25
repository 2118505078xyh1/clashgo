package ui

import (
	"fmt"
	"os"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/autostart"
	"clashgo/internal/lightweight"
	"clashgo/internal/paths"
	"clashgo/internal/service"
)

// pageSettings 是设置页。
//
// 设计原则：只留下日常会用到的开关和按钮，其余（内核调试、备份、远程同步、
// 资源管理等）收进「高级工具」或直接移除，避免一屏几十个键。
func (a *App) pageSettings(c *ui.Context) {
	ui.Scroll(c).Grow(1).Padding(spaceLg).Gap(spaceMd).Children(func() {
		a.pageHeader(c, nil)

		// 内核：端口与重启。
		card(c, func() {
			sectionTitle(c, "内核", "端口与控制")
			ui.Row(c).Gap(spaceMd).AlignItems(ui.Center).Children(func() {
				ui.Column(c).Gap(2).Children(func() {
					text(c, "混合").FontSize(11).TextColor(ui.Hex(textTertiary))
					ui.TextInput(c, &a.portText).Placeholder("7897").Width(96).Submitted()
				})
				ui.Column(c).Gap(2).Children(func() {
					text(c, "SOCKS").FontSize(11).TextColor(ui.Hex(textTertiary))
					ui.TextInput(c, &a.socksPortText).Width(96).Submitted()
				})
				ui.Column(c).Gap(2).Children(func() {
					text(c, "HTTP").FontSize(11).TextColor(ui.Hex(textTertiary))
					ui.TextInput(c, &a.httpPortText).Width(96).Submitted()
				})
				ui.Column(c).Gap(2).Children(func() {
					text(c, " ").FontSize(11)
					pillButton(c, "应用", "应用端口配置", func() { a.applyPorts() })
				})
				ui.Spacer(c).Grow(1)
				ui.Column(c).Gap(2).Children(func() {
					text(c, " ").FontSize(11)
					ui.Row(c).Gap(spaceSm).Children(func() {
						ui.Checkbox(c, &a.Settings.SocksEnabled, "SOCKS")
						ui.Checkbox(c, &a.Settings.HTTPEnabled, "HTTP")
						pillButton(c, "检查占用", "检查端口是否被其它程序占用", func() { a.checkPorts() })
					})
				})
			})
			if a.EffectivePort > 0 && a.EffectivePort != a.Settings.MixedPort {
				text(c, "本次回退端口: "+itoaLocal(a.EffectivePort)).
					FontSize(11).TextColor(ui.Hex(colorWarning))
			}
			ui.Row(c).Gap(spaceSm).AlignItems(ui.Center).Children(func() {
				pillButton(c, "重启内核", "重新加载当前配置", func() { a.reapplyCore() })
				pillButton(c, "查看运行时配置", "查看当前生效的配置文件", func() { a.showRuntimeConfig() })
				ui.Spacer(c).Grow(1)
				// 服务模式只对 TUN 有用，平时不显示。
				if a.Settings.EnableTUN {
					pillButton(c, "安装服务", "以服务模式运行以获得 TUN 所需权限", func() {
						exe, _ := os.Executable()
						if err := service.InstallService(exe); err != nil {
							a.notify("安装服务", err.Error())
						} else {
							_ = service.StartService()
							a.notify("安装服务", "服务已安装并启动")
						}
					})
				}
			})
			if a.Settings.EnableTUN && !service.IsAdmin() {
				text(c, "⚠ TUN 模式需要管理员权限，请以管理员身份运行，或安装服务模式。").
					FontSize(11).TextColor(ui.Hex(colorWarning))
			}
		})

		// 开关：按需启用，每项一行。
		card(c, func() {
			sectionTitle(c, "开关", "按需启用")
			// 按网络自动开关
			ui.Row(c).Gap(spaceMd).AlignItems(ui.Center).Children(func() {
				text(c, "按网络自动开关").FontSize(12).Width(112)
				if a.Settings.EnableSSIDRule {
					ui.TextInput(c, &a.Settings.SSIDAllowlist).Grow(1).Placeholder("留空 = 所有网络")
				} else {
					ui.Spacer(c).Grow(1)
				}
				if ui.Switch(c, &a.Settings.EnableSSIDRule).Changed() {
					a.mustSaveSettings()
				}
			})
			// 轻量模式
			ui.Row(c).Gap(spaceMd).AlignItems(ui.Center).Children(func() {
				text(c, "轻量模式").FontSize(12).Width(112)
				if a.Settings.EnableLightweight {
					ui.TextInput(c, &a.lightweightText).Width(72).Placeholder("10")
					text(c, "分钟").FontSize(11).TextColor(ui.Hex(textTertiary))
					pillButton(c, "应用", "应用空闲时长", func() {
						var mins int
						if _, err := fmt.Sscan(a.lightweightText, &mins); err == nil && mins > 0 {
							a.Settings.LightweightMinutes = mins
							a.Lightweight = lightweight.New(mins,
								func() { a.Kernel.Suspend() }, func() { a.Kernel.Resume() })
							a.Lightweight.SetEnabled(true)
							a.mustSaveSettings()
						}
					})
					status := "运行中"
					if a.Lightweight.Suspended() {
						status = "已暂停"
					}
					text(c, status).FontSize(11).TextColor(ui.Hex(textTertiary))
				} else {
					ui.Spacer(c).Grow(1)
				}
				if ui.Switch(c, &a.Settings.EnableLightweight).Changed() {
					a.Lightweight.SetEnabled(a.Settings.EnableLightweight)
					a.mustSaveSettings()
				}
			})
			// 开机自启
			ui.Row(c).Gap(spaceMd).AlignItems(ui.Center).Children(func() {
				text(c, "开机自启").FontSize(12).Width(112)
				ui.Spacer(c).Grow(1)
				if ui.Switch(c, &a.Settings.AutoLaunch).Changed() {
					if a.Settings.AutoLaunch {
						if err := autostart.Enable("ClashGo"); err != nil {
							a.notify("错误", err.Error())
						}
					} else {
						_ = autostart.Disable("ClashGo")
					}
					a.mustSaveSettings()
				}
			})
		})

		// 高级工具：内核调试与少用的功能都收在这里。
		card(c, func() {
			sectionTitle(c, "高级工具", "内核调试与少用功能")
			ui.Row(c).Gap(spaceSm).Wrap().Children(func() {
				if ui.Button(c, "规则").Clicked() {
					a.router.Push("/rules")
				}
				if ui.Button(c, "日志").Clicked() {
					a.router.Push("/logs")
				}
				if ui.Button(c, "DNS 查询").Clicked() {
					a.router.Push("/dns")
				}
				if ui.Button(c, "请求记录").Clicked() {
					a.router.Push("/requests")
				}
				if ui.Button(c, "资源更新").Clicked() {
					a.ShowResources()
				}
				if ui.Button(c, "节点链").Clicked() {
					a.ShowProfileChain()
				}
				if ui.Button(c, "安全设置").Clicked() {
					a.ShowSafe()
				}
			})
		})

		// 关于
		card(c, func() {
			sectionTitle(c, "关于", "ClashGo")
			text(c, "纯 Go 实现的 Clash 桌面客户端 · mihomo 内核 + MyGo 原生 UI").
				FontSize(12).TextColor(ui.Hex(textTertiary))
			ui.Row(c).Gap(spaceSm).Children(func() {
				pillButton(c, "打开数据目录", "打开配置与订阅所在目录", func() { openPath(paths.Home) })
				pillButton(c, "检查更新", "检查是否有新版本", func() { a.checkUpdate() })
			})
		})
	})
}
