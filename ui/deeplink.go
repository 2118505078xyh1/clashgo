package ui

import (
	"net/url"
	"time"
)

// HandleOpenURL imports a subscription from a clash://install-config deep
// link, e.g. clash://install-config?url=<encoded-subscription-url>.
func (a *App) HandleOpenURL(raw string) {
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	// Accept standard Clash install-config schemes.
	sub := ""
	switch u.Scheme {
	case "clash", "clashmeta":
		sub = u.Query().Get("url")
	}
	if sub == "" {
		return
	}
	a.win.Update(func() {
		a.PendingURL = sub
		a.ImportName = "订阅 " + timeNowShort()
		a.ImportDialog = true
	})
}

func timeNowShort() string {
	return time.Now().Format("01-02 15:04")
}
