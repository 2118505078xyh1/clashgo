//go:build windows

package sysproxy

import (
	"testing"
	"unsafe"
)

// TestEnumRASConnections makes sure the RAS probe and buffer-growth path never
// panics. CI machines normally have no dial-up entries, in which case an empty
// list (or a "not available" error) is perfectly fine.
func TestEnumRASConnections(t *testing.T) {
	connections, err := enumRASConnections()
	if err != nil {
		t.Logf("RAS enumeration unavailable (expected without a phonebook): %v", err)
		return
	}
	t.Logf("found %d RAS connection(s)", len(connections))
	for _, name := range connections {
		t.Logf("connection: %s", name)
	}
}

// TestRAStructLayout documents the ABI sizes we rely on when calling
// RasEnumEntriesW and InternetSetOptionW.
func TestRAStructLayout(t *testing.T) {
	if got := unsafe.Sizeof(rasEntryName{}); got != 520 {
		t.Errorf("rasEntryName size = %d, want 520", got)
	}
	ptrSize := unsafe.Sizeof(uintptr(0))
	want := uintptr(12) + 2*ptrSize // three DWORDs + two pointers
	if ptrSize == 8 {
		want += 4 // padding after dwSize on 64-bit
	}
	if got := unsafe.Sizeof(internetPerConnOptionList{}); got != want {
		t.Errorf("INTERNET_PER_CONN_OPTION_LISTW size = %d, want %d", got, want)
	}
}
