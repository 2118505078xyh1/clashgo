package ui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/config"
	"clashgo/internal/profile"
)

// The chain dialog keeps its toggle and widget state at package scope so we
// don't have to widen the App struct just for this overlay.
var (
	chainOpen     bool
	chainPrevName = chainNone
	chainNextName = chainNone
	chainPortText string
)

const chainNone = "（无）"

// ShowProfileChain schedules the profile-chain dialog for the next frame and
// seeds its widgets from the currently selected profile's options.
func (a *App) ShowProfileChain() {
	chainOpen = true
	if a == nil || a.Profiles == nil || a.Profiles.DB == nil {
		return
	}
	db := a.Profiles.DB
	cur := db.CurrentItem()
	if cur == nil {
		return
	}
	chainPrevName = chainOptionName(db, cur, true)
	chainNextName = chainOptionName(db, cur, false)
	chainPortText = ""
	if cur.Option != nil {
		chainPortText = fmt.Sprint(cur.Option.PreSocksPort)
	}
}

func chainOptionName(db *config.ProfilesDB, item *config.PrfItem, prev bool) string {
	if item == nil || item.Option == nil || db == nil {
		return chainNone
	}
	uid := item.Option.NextProfile
	if prev {
		uid = item.Option.PrevProfile
	}
	if uid == "" {
		return chainNone
	}
	if it := db.Find(uid); it != nil {
		return it.Name
	}
	return chainNone
}

func chainUIDForName(db *config.ProfilesDB, name string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == chainNone || db == nil {
		return ""
	}
	for _, it := range db.Items {
		if it.Name == name {
			return it.UID
		}
	}
	return ""
}

// overlayProfileChain shows the prev -> current -> next UID chain and lets the
// user rewire Prev/Next (and the preceding hop's SOCKS port). Changes are
// written back to PrfOption and persisted through a.Profiles.Save().
func (a *App) overlayProfileChain(c *ui.Context) {
	ui.Modal(c, &chainOpen, func() {
		ui.Column(c).Width(520).Height(480).Padding(24).Gap(12).
			Background(c.Theme().Surface).Radius(12).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				text(c, "订阅节点链").FontSize(18).Bold().Grow(1)
				if ui.Button(c, "关闭").Clicked() {
					chainOpen = false
				}
			})

			db := a.Profiles.DB
			cur := db.CurrentItem()
			if cur == nil {
				text(c, "当前没有选中的订阅").TextColor(c.Theme().TextMuted)
				return
			}
			if cur.Option == nil {
				cur.Option = &config.PrfOption{}
			}
			text(c, "当前订阅："+cur.Name).TextColor(c.Theme().TextMuted)
			text(c, "链路顺序：前置 → 当前 → 后置（循环引用会自动断开）").
				FontSize(11).TextColor(c.Theme().TextMuted)

			// Visualize the expanded chain.
			ui.Scroll(c).Gap(4).Children(func() {
				for i, uid := range profile.BuildChain(db, cur) {
					it := db.Find(uid)
					name := uid
					if it != nil {
						name = it.Name
					}
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Badge(c, fmt.Sprint(i+1)).Width(30)
						text(c, name).Grow(1)
					})
				}
			})

			// Dropdowns list every other profile plus an explicit "none".
			options := []string{chainNone}
			for _, it := range db.Items {
				if it.UID != cur.UID {
					options = append(options, it.Name)
				}
			}
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				text(c, "前置订阅").Width(80)
				ui.Combobox(c, &chainPrevName, options).Grow(1)
			})
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				text(c, "后置订阅").Width(80)
				ui.Combobox(c, &chainNextName, options).Grow(1)
			})
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				text(c, "前置 SOCKS 端口").Width(120)
				ui.TextInput(c, &chainPortText)
			})

			// Persist anything the user changed this frame.
			changed := false
			if uid := chainUIDForName(db, chainPrevName); uid != cur.Option.PrevProfile {
				cur.Option.PrevProfile = uid
				changed = true
			}
			if uid := chainUIDForName(db, chainNextName); uid != cur.Option.NextProfile {
				cur.Option.NextProfile = uid
				changed = true
			}
			if port, err := strconv.Atoi(strings.TrimSpace(chainPortText)); err == nil && port >= 0 && port != cur.Option.PreSocksPort {
				cur.Option.PreSocksPort = port
				changed = true
			}
			if changed {
				if err := a.Profiles.Save(); err != nil {
					a.notify("保存失败", err.Error())
				}
			}

			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.PrimaryButton(c, "保存并关闭").Clicked() {
					chainOpen = false
				}
			})
		})
	})
}
