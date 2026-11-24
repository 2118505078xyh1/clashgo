package profile

import (
	"testing"
	"time"

	"clashgo/internal/config"
)

func TestNextUpdateEligibility(t *testing.T) {
	now := time.Now().Unix()
	cases := []struct {
		name string
		item *config.PrfItem
		want bool
	}{
		{
			"local profile skipped",
			&config.PrfItem{Type: config.ProfileLocal, Option: &config.PrfOption{AllowAutoUpdate: true, UpdateInterval: 10}},
			false,
		},
		{
			"auto-update disabled",
			&config.PrfItem{Type: config.ProfileRemote, Updated: now, Option: &config.PrfOption{AllowAutoUpdate: false, UpdateInterval: 10}},
			false,
		},
		{
			"zero interval skipped",
			&config.PrfItem{Type: config.ProfileRemote, Updated: now, Option: &config.PrfOption{AllowAutoUpdate: true, UpdateInterval: 0}},
			false,
		},
		{
			"nil option skipped",
			&config.PrfItem{Type: config.ProfileRemote, Updated: now},
			false,
		},
		{
			"eligible",
			&config.PrfItem{Type: config.ProfileRemote, Updated: now, Option: &config.PrfOption{AllowAutoUpdate: true, UpdateInterval: 10}},
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := nextUpdate(tc.item)
			if ok != tc.want {
				t.Fatalf("eligibility = %v, want %v", ok, tc.want)
			}
		})
	}
}

func TestNextUpdateTiming(t *testing.T) {
	now := time.Now().Unix()
	item := &config.PrfItem{
		Type: config.ProfileRemote, Updated: now,
		Option: &config.PrfOption{AllowAutoUpdate: true, UpdateInterval: 10},
	}
	at, ok := nextUpdate(item)
	if !ok {
		t.Fatal("expected eligible")
	}
	want := time.Unix(now, 0).Add(10 * time.Minute)
	if !at.Equal(want) {
		t.Fatalf("next update = %v, want %v", at, want)
	}
}

func TestNextUpdateOverdueInPast(t *testing.T) {
	// 很久之前更新的订阅，其下次时间应在过去（timer 会立即触发）。
	old := time.Now().Add(-2 * time.Hour).Unix()
	item := &config.PrfItem{
		Type: config.ProfileRemote, Updated: old,
		Option: &config.PrfOption{AllowAutoUpdate: true, UpdateInterval: 10},
	}
	at, ok := nextUpdate(item)
	if !ok {
		t.Fatal("expected eligible")
	}
	if !at.Before(time.Now()) {
		t.Fatalf("overdue subscription next update should be in the past, got %v", at)
	}
}

func TestProfileTimerStartStop(t *testing.T) {
	mgr := &Manager{DB: &config.ProfilesDB{}}
	timer := NewTimer(mgr, nil)
	timer.Start()
	timer.Start() // 幂等
	timer.Refresh()
	if _, ok := timer.GetNextUpdateTime("nonexistent"); ok {
		t.Fatal("unexpected schedule for unknown uid")
	}
	timer.Stop()
}
