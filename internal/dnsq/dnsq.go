// Package dnsq parses 自研内核's [DNS] log lines into structured query records.
package dnsq

import (
	"regexp"
	"strings"
)

// Record is one DNS resolution event.
type Record struct {
	Time   string `json:"time"`
	Domain string `json:"domain"`
	Answer string `json:"answer"`
	Server string `json:"server"`
	Type   string `json:"type"` // hit | query | resolve | error
}

var (
	resolveRe = regexp.MustCompile(`^\[DNS\]\s+(\S+)\s+-->\s+(.+?)(?:\s+from\s+(\S+))?$`)
	hitRe     = regexp.MustCompile(`^\[DNS\]\s+cache hit\s+(\S+)\s+-->\s+(.+?)(?:,|$)`)
	queryRe   = regexp.MustCompile(`^\[DNS\]\s+resolve\s+(\S+)\s+(\S+)\s+from\s+(\S+)$`)
)

// Parse turns a log payload into a DNS Record, if it is a DNS line.
func Parse(timeStr, payload string) (Record, bool) {
	if !strings.HasPrefix(payload, "[DNS]") {
		return Record{}, false
	}
	r := Record{Time: timeStr}
	if m := hitRe.FindStringSubmatch(payload); m != nil {
		r.Type = "hit"
		r.Domain, r.Answer = m[1], trim(m[2])
		return r, true
	}
	if m := queryRe.FindStringSubmatch(payload); m != nil {
		r.Type = "query"
		r.Domain, r.Answer, r.Server = m[1], m[2]+" ?", m[3]
		return r, true
	}
	if m := resolveRe.FindStringSubmatch(payload); m != nil {
		r.Type = "resolve"
		r.Domain, r.Answer, r.Server = m[1], trim(m[2]), m[3]
		return r, true
	}
	r.Type = "error"
	r.Answer = strings.TrimPrefix(payload, "[DNS] ")
	return r, true
}

func trim(s string) string { return strings.TrimSuffix(strings.TrimSpace(s), ",") }
