package sysproxy

import (
	"testing"
)

func TestItoa(t *testing.T) {
	cases := map[int]string{0: "0", 7: "7", 7897: "7897", 65535: "65535"}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Fatalf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestServerMatchesPort(t *testing.T) {
	cases := []struct {
		server string
		port   int
		want   bool
	}{
		{"127.0.0.1:7897", 7897, true},
		{"localhost:7897", 7897, true},
		{"[::1]:7897", 7897, true},
		{"127.0.0.1:7890", 7897, false},
		{"127.0.0.1:78970", 7897, false},
		{"", 7897, false},
	}
	for _, c := range cases {
		if got := serverMatchesPort(c.server, c.port); got != c.want {
			t.Fatalf("serverMatchesPort(%q, %d) = %v, want %v", c.server, c.port, got, c.want)
		}
	}
}
