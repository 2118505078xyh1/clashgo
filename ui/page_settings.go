package ui

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"clashgo/internal/autostart"
	"clashgo/internal/backup"
	"clashgo/internal/diagnostic"
	"clashgo/internal/hidewin"
	"clashgo/internal/lightweight"
	"clashgo/internal/paths"
	"clashgo/internal/service"
	"clashgo/internal/sysproxy"
	"clashgo/internal/webdav"
)

func (a *App) pageSettings(c *ui.Context) {
	ui.Scroll(c).Grow(1).Padding(20).Gap(16).Children(func() {
		a.pageHeader(c, a.tr("settings"), nil)

		// DNS 查询与请求记录没有侧边栏入口，这里保留跳转。
		card(c, func() {
			sectionTitle(c, "工具", "DNS 查询 / 请求记录")
			ui.Row(c).Gap(8).Wrap().Children(func() {
				toolButton(c, iconGlobe, "DNS 查询", partyWarning, func() { a.router.Push("/dns") })
				toolButton(c, iconClock, "请求记录", partyDanger, func() { a.router.Push("/requests") })
			})
		})

		card(c, func() {
			sectionTitle(c, "外观", "Clash Party 暗色主题")
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				text(c, "配色").Width(120)
				ui.Badge(c, "暗色 · 主色 "+partyPrimary).Padding(4, 10).
					Background(withAlpha(ui.Hex(partyPrimary), 0.18)).TextColor(ui.Hex(partyPrimary))
			})
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				text(c, "强调色").Width(120)
				colors := []string{partyPrimary, "#8b5cf6", partySuccess, partyWarning, partyDanger}
				for _, col := range colors {
					if ui.Button(c, "  ").Background(ui.Hex(col)).Radius(partyRadiusSmall).Width(28).Clicked() {
						a.Settings.PrimaryColor = col
						a.mustSaveSettings()
					}
				}
				if ui.Button(c, "取色器").Clicked() {
					a.openColorPicker()
				}
			})
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				text(c, "界面语言").Width(120)
				text(c, "简体中文（默认）").TextColor(c.Theme().TextMuted)
			})
		})

		card(c, func() {
			sectionTitle(c, "内核", "端口与控制")
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				text(c, "混合端口").Width(140)
				if ui.TextInput(c, &a.portText).Placeholder("7897").Width(120).Submitted() {
					a.applyPort()
				}
				ui.Button(c, a.trs("应用")).OnClick(a.applyPort)
				if a.effectivePort > 0 && a.effectivePort != a.Settings.MixedPort {
					text(c, "本次回退端口: "+itoaLocal(a.effectivePort)).
						FontSize(11).TextColor(c.Theme().Warning)
				}
			})
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				text(c, "SOCKS 端口").Width(140)
				if ui.TextInput(c, &a.socksPortText).Width(120).Submitted() {
					a.applyPorts()
				}
				ui.Checkbox(c, &a.Settings.SocksEnabled, "启用")
			})
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				text(c, "HTTP 端口").Width(140)
				if ui.TextInput(c, &a.httpPortText).Width(120).Submitted() {
					a.applyPorts()
				}
				ui.Checkbox(c, &a.Settings.HTTPEnabled, "启用")
			})
			if ui.Button(c, "检查端口占用").Clicked() {
				a.checkPorts()
			}
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				text(c, "外部控制").Width(140)
				text(c, a.Settings.ExternalController).TextColor(c.Theme().TextMuted)
			})
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				text(c, "日志级别").Width(140)
				levels := []string{"debug", "info", "warning", "error"}
				for _, lv := range levels {
					if a.Settings.LogLevel == lv {
						ui.PrimaryButton(c, lv).OnClick(func(v string) func() {
							return func() { a.Settings.LogLevel = v; a.mustSaveSettings(); a.reapplyCore() }
						}(lv))
					} else if ui.Button(c, lv).Clicked() {
						a.Settings.LogLevel = lv
						a.mustSaveSettings()
						a.reapplyCore()
					}
				}
			})
			ui.Row(c).Gap(8).Padding(4, 0).Children(func() {
				if ui.PrimaryButton(c, a.tr("restart_core")).Clicked() {
					a.reapplyCore()
				}
				if ui.Button(c, "查看运行时配置").Clicked() {
					a.showRuntimeConfig()
				}
				if ui.Button(c, "增强过程").Clicked() {
					a.PipelineOpen = true
				}
			})
			// TUN privilege guidance.
			if a.Settings.EnableTUN && !service.IsAdmin() {
				text(c, "⚠ TUN 模式需要管理员权限，请以管理员身份运行，或安装服务模式。").
					FontSize(12).TextColor(c.Theme().Warning)
			}
			ui.Row(c).Gap(8).Padding(4, 0).Children(func() {
				if ui.Button(c, a.trs("安装服务")).Clicked() {
					exe, _ := os.Executable()
					if err := service.InstallService(exe); err != nil {
						a.notify("安装服务", err.Error())
					} else {
						_ = service.StartService()
						a.notify("安装服务", "服务已安装并启动")
					}
				}
				if ui.Button(c, a.trs("卸载服务")).Clicked() {
					if err := service.UninstallService(); err != nil {
						a.notify("卸载服务", err.Error())
					} else {
						a.notify("卸载服务", "服务已卸载")
					}
				}
			})
		})

		card(c, func() {
			sectionTitle(c, "DNS 覆盖", "自定义 DNS 服务器（保留订阅其它 DNS 配置）")
			ui.Row(c).Gap(8).Children(func() {
				text(c, "启用 DNS 覆盖").Grow(1)
				if ui.Switch(c, &a.Settings.EnableDNSOverride).Changed() {
					a.mustSaveSettings()
					a.reapplyCore()
				}
			})
			if a.Settings.EnableDNSOverride {
				ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
					text(c, "DNS 服务器").Width(120)
					ui.TextInput(c, &a.Settings.Nameserver).Grow(1)
				})
				text(c, "多个用英文逗号分隔；覆盖仅替换 nameserver，保留 fake-ip/规则等设置").
					FontSize(11).TextColor(c.Theme().TextMuted)
			}
		})

		card(c, func() {
			sectionTitle(c, "测试", "延迟检测")
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				text(c, "测试地址").Width(140)
				ui.TextInput(c, &a.Settings.LatencyTestURL).Grow(1)
			})
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				text(c, "超时 (ms)").Width(140)
				ui.TextInput(c, &a.timeoutText).Width(100)
				ui.Button(c, a.trs("应用")).OnClick(a.applyTimeout)
			})
		})

		card(c, func() {
			sectionTitle(c, "按网络自动开关", "根据 Wi-Fi 名称自动切换系统代理")
			ui.Row(c).Gap(8).Children(func() {
				text(c, "启用").Grow(1)
				if ui.Switch(c, &a.Settings.EnableSSIDRule).Changed() {
					a.mustSaveSettings()
				}
			})
			if a.Settings.EnableSSIDRule {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					text(c, "代理开启的 Wi-Fi").Width(140)
					ui.TextInput(c, &a.Settings.SSIDAllowlist).Grow(1)
				})
				text(c, "多个名称用英文逗号分隔；留空表示所有网络都开启代理").
					FontSize(11).TextColor(c.Theme().TextMuted)
			}
		})

		card(c, func() {
			sectionTitle(c, "轻量模式", "空闲时暂停内核以降低占用")
			ui.Row(c).Gap(8).Children(func() {
				text(c, "启用轻量模式").Grow(1)
				if ui.Switch(c, &a.Settings.EnableLightweight).Changed() {
					a.Lightweight.SetEnabled(a.Settings.EnableLightweight)
					a.mustSaveSettings()
				}
			})
			if a.Settings.EnableLightweight {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					text(c, "空闲时长(分钟)").Width(140)
					ui.TextInput(c, &a.lightweightText).Width(80)
					if ui.Button(c, a.trs("应用")).Clicked() {
						var mins int
						if _, err := fmt.Sscan(a.lightweightText, &mins); err == nil && mins > 0 {
							a.Settings.LightweightMinutes = mins
							a.Lightweight = lightweight.New(mins,
								func() { a.Kernel.Suspend() }, func() { a.Kernel.Resume() })
							a.Lightweight.SetEnabled(true)
							a.mustSaveSettings()
						}
					}
				})
				status := "运行中"
				if a.Lightweight.Suspended() {
					status = "已暂停（有流量时自动恢复）"
				}
				text(c, "当前状态: "+status).FontSize(12).TextColor(c.Theme().TextMuted)
			}
		})

		card(c, func() {
			sectionTitle(c, "启动", "开机自启")
			ui.Row(c).Gap(8).Children(func() {
				text(c, "登录时自动启动").Grow(1)
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

		card(c, func() {
			sectionTitle(c, "热键", "全局快捷键")
			ui.Row(c).Gap(8).Children(func() {
				text(c, "启用热键").Grow(1)
				if ui.Switch(c, &a.Settings.EnableHotkeys).Changed() {
					if !a.Settings.EnableHotkeys {
						mygo.GlobalShortcut.UnregisterAll()
					} else {
						a.RegisterHotkeys(a.win)
					}
					a.mustSaveSettings()
				}
			})
			if a.Settings.EnableHotkeys {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					text(c, "切换系统代理").Width(140)
					ui.TextInput(c, &a.Settings.HotkeyToggle).Width(220)
				})
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					text(c, "显示/隐藏窗口").Width(140)
					ui.TextInput(c, &a.Settings.HotkeyShow).Width(220)
				})
				text(c, "格式如 CmdOrCtrl+Shift+S，重启应用后生效").
					FontSize(11).TextColor(c.Theme().TextMuted)
			}
		})

		card(c, func() {
			sectionTitle(c, "PAC 自动代理", "内嵌 PAC 文件服务")
			ui.Row(c).Gap(8).Children(func() {
				text(c, "启用 PAC 服务").Grow(1)
				if ui.Switch(c, &a.Settings.EnablePAC).Changed() {
					if a.Settings.EnablePAC {
						if _, err := a.PAC.Start(); err != nil {
							a.notify("错误", err.Error())
						}
					} else {
						a.PAC.Stop()
						a.Settings.EnablePACSystem = false
						_ = sysproxy.SetAutoProxy(false, "")
					}
					a.mustSaveSettings()
				}
			})
			if a.Settings.EnablePAC {
				text(c, "PAC 地址: "+a.PAC.URL()).FontSize(12).TextColor(c.Theme().TextMuted)
				ui.Row(c).Gap(8).Padding(4, 0).Children(func() {
					text(c, "设置为系统自动代理").Grow(1)
					if ui.Switch(c, &a.Settings.EnablePACSystem).Changed() {
						if a.Settings.EnablePACSystem {
							if err := sysproxy.SetAutoProxy(true, a.PAC.URL()); err != nil {
								a.notify("错误", err.Error())
							}
						} else {
							_ = sysproxy.SetAutoProxy(false, "")
						}
						a.mustSaveSettings()
					}
				})
				ui.TextArea(c, &a.PACContentText).Height(100)
				if ui.Button(c, "保存 PAC 脚本").Clicked() {
					a.Settings.PACContent = a.PACContentText
					a.PAC.SetContent(a.PACContentText)
					a.mustSaveSettings()
				}
			}
		})

		card(c, func() {
			sectionTitle(c, "WebDAV 备份", "远程同步")
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				text(c, "服务器").Width(80)
				ui.TextInput(c, &a.Settings.WebDAVURL).Placeholder("https://dav.example.com").Grow(1)
			})
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				text(c, "用户名").Width(80)
				ui.TextInput(c, &a.Settings.WebDAVUsername).Width(180)
				text(c, "密码").Padding(8, 0, 0, 0)
				ui.TextInput(c, &a.Settings.WebDAVPassword).Password().Width(180)
			})
			ui.Row(c).Gap(8).Padding(4, 0).Children(func() {
				if ui.Button(c, a.trs("保存设置")).Clicked() {
					a.mustSaveSettings()
					a.notify("WebDAV", "设置已保存")
				}
				if ui.Button(c, "测试连接").Clicked() {
					go func() {
						err := webdav.New(webdav.Config{
							URL: a.Settings.WebDAVURL, Username: a.Settings.WebDAVUsername,
							Password: a.Settings.WebDAVPassword,
						}).TestConnection()
						a.win.Update(func() {
							if err != nil {
								a.notify("连接失败", err.Error())
							} else {
								a.notify("连接成功", "WebDAV 服务器可用")
							}
						})
					}()
				}
				if ui.Button(c, "上传备份").Clicked() {
					a.webdavUpload()
				}
				if ui.Button(c, "列出备份").Clicked() {
					go func() {
						files, err := a.webdavClient().List()
						a.win.Update(func() {
							if err != nil {
								a.notify("错误", err.Error())
							} else {
								a.WebDAVFiles = files
							}
						})
					}()
				}
			})
			for _, f := range a.WebDAVFiles {
				file := f
				ui.Row(c).Gap(8).Padding(4, 0).Children(func() {
					text(c, file.Name).Grow(1)
					text(c, file.LastModified.Format("2006-01-02 15:04")).TextColor(c.Theme().TextMuted)
					if ui.Button(c, a.trs("恢复")).Clicked() {
						a.webdavRestore(file.Name)
					}
				})
			}
		})

		card(c, func() {
			sectionTitle(c, "备份", "本地配置备份与恢复")
			ui.Row(c).Gap(8).Children(func() {
				if ui.PrimaryButton(c, a.tr("auto_backup")).Clicked() {
					name, err := backup.Create()
					if err != nil {
						a.notify("备份失败", err.Error())
					} else {
						a.notify("备份完成", "备份名称："+name)
					}
				}
				if ui.Button(c, "刷新列表").Clicked() {
					a.refreshBackups()
				}
			})
			ui.Divider(c)
			for _, b := range a.Backups {
				bak := b
				ui.Row(c).Gap(8).Padding(4, 0).Children(func() {
					text(c, bak.Name).Grow(1)
					text(c, bak.Time.Format("2006-01-02 15:04")).TextColor(c.Theme().TextMuted)
					if ui.Button(c, a.trs("恢复")).Clicked() {
						a.restoreBackup(bak.Name)
					}
				})
			}
			if len(a.Backups) == 0 {
				text(c, a.trs("暂无备份")).TextColor(c.Theme().TextMuted).FontSize(12)
			}
		})

		card(c, func() {
			sectionTitle(c, "高级工具", "资源管理 / 节点链 / 安全 / Web API")
			ui.Row(c).Gap(8).AlignItems(ui.Center).Padding(2, 0).Children(func() {
				text(c, "代理守护").Grow(1)
				if ui.Switch(c, &a.Settings.EnableProxyGuard).Changed() {
					a.mustSaveSettings()
					a.refreshGuard()
				}
			})
			ui.Row(c).Gap(8).Wrap().Children(func() {
				if ui.Button(c, "资源更新").Clicked() {
					a.ShowResources()
				}
				if ui.Button(c, "节点链").Clicked() {
					a.ShowProfileChain()
				}
				if ui.Button(c, "安全设置").Clicked() {
					a.ShowSafe()
				}
				if ui.Button(c, "窗口几何").Clicked() {
					a.ShowWindowGeo()
				}
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					text(c, "网络接口").Grow(1)
					if ui.Switch(c, &a.Settings.WebAPIEnabled).Changed() {
						a.mustSaveSettings()
						if a.Settings.WebAPIEnabled {
							a.startWebAPI()
						} else if a.WebAPIServer != nil {
							a.WebAPIServer.Close()
							a.WebAPIServer = nil
						}
					}
				})
			})
		})

		card(c, func() {
			sectionTitle(c, "关于", "ClashGo")
			text(c, "纯 Go 实现的 Clash 桌面客户端 · 自研内核 + MyGo 原生 UI").
				FontSize(12).TextColor(c.Theme().TextMuted)
			if ui.Button(c, a.trs("打开数据目录")).Clicked() {
				openPath(paths.Home)
			}
			if ui.Button(c, a.trs("复制诊断信息")).Clicked() {
				mygo.Clipboard.WriteText(diagnostic.Collect("1.0.0").Text())
				a.notify("诊断信息", "已复制到剪贴板")
			}
			if ui.Button(c, a.trs("复制代理命令")).Clicked() {
				port := a.Settings.MixedPort
				if a.effectivePort > 0 {
					port = a.effectivePort
				}
				env := fmt.Sprintf("export http_proxy=http://127.0.0.1:%d\nexport https_proxy=http://127.0.0.1:%d\nexport all_proxy=socks5://127.0.0.1:%d", port, port, port)
				mygo.Clipboard.WriteText(env)
				a.notify("代理命令", "已复制到剪贴板")
			}
			ui.Row(c).Gap(8).Padding(4, 0).AlignItems(ui.Center).Children(func() {
				if a.LatestRelease != nil {
					text(c, "最新版本: "+a.LatestRelease.TagName).TextColor(c.Theme().Success)
					if ui.Button(c, "下载更新").Clicked() {
						asset := a.LatestRelease.AssetForPlatform(runtime.GOOS, runtime.GOARCH)
						_ = mygo.Shell.OpenExternal(asset)
					}
				} else if ui.Button(c, a.tr("check_update")).Clicked() {
					a.checkUpdate()
				}
			})
		})
	})
}

func (a *App) setThemeMode(mode string) {
	a.Settings.ThemeMode = mode
	a.mustSaveSettings()
}

func (a *App) applyPort() {
	var port int
	if _, err := fmtSscan(a.portText, &port); err != nil || port < 1 || port > 65535 {
		a.notify("错误", "端口号无效")
		return
	}
	a.Settings.MixedPort = port
	a.mustSaveSettings()
	a.applySystemProxy()
	a.reapplyCore()
}

func (a *App) applyTimeout() {
	var ms int
	if _, err := fmtSscan(a.timeoutText, &ms); err != nil || ms < 100 {
		a.notify("错误", "超时时间无效")
		return
	}
	a.Settings.LatencyTimeout = ms
	a.mustSaveSettings()
}

func openPath(path string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = hidewin.Command("explorer", path)
	case "darwin":
		cmd = exec.Command("open", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	_ = cmd.Start()
}
