// Package listener probes whether an address/port/transport is bindable,
// mirroring a reference GUI's probe_listener command.
package listener

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ProbeOutcome describes the result of a listener probe.
type ProbeOutcome struct {
	Available bool   `json:"available"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Reason    string `json:"reason"`
}

// Probe checks whether addr:port can be bound for the given transport
// ("tcp", "udp", or "both").
func Probe(addr string, port int, transport string) ProbeOutcome {
	out := ProbeOutcome{Address: addr, Port: port, Transport: transport}
	if port < 1 || port > 65535 {
		out.Reason = "port out of range"
		return out
	}
	networks := []string{"tcp"}
	switch strings.ToLower(transport) {
	case "udp":
		networks = []string{"udp"}
	case "both":
		networks = []string{"tcp", "udp"}
	}
	target := net.JoinHostPort(addr, strconv.Itoa(port))
	for _, network := range networks {
		ln, err := net.Listen(network, target)
		if err != nil {
			out.Reason = fmt.Sprintf("%s bind failed: %v", network, err)
			return out
		}
		_ = ln.Close()
	}
	out.Available = true
	return out
}

// CheckSet probes a set of ports, returning conflicts.
func CheckSet(ports map[string]int, transport string) []ProbeOutcome {
	var conflicts []ProbeOutcome
	seen := map[string]bool{}
	for name, port := range ports {
		if port == 0 {
			continue
		}
		key := fmt.Sprintf("%s:%d/%s", name, port, transport)
		if seen[key] {
			continue
		}
		seen[key] = true
		res := Probe("127.0.0.1", port, transport)
		if !res.Available {
			res.Reason = name + ": " + res.Reason
			conflicts = append(conflicts, res)
		}
	}
	return conflicts
}

// WaitFree polls until a port becomes bindable or timeout elapses.
func WaitFree(addr string, port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if Probe(addr, port, "tcp").Available {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}
