package quicproto

import (
	"encoding/hex"
	"testing"
)

// RFC 9001 Appendix A.1: DCID = 8394c8f03e515708
func TestInitialKeyDerivationVector(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	k := deriveInitialKeys(dcid)
	// 期望值来自 RFC 9001 A.1 / quic-go initial_aead_test.go
	wantClientKey := "1f369613dd76d5467730efcbe3b1a22d"
	wantClientIV := "fa044b2f42a3fd3b46fb255c"
	wantClientHP := "9f50449e04a0e810283a1e9933adedd2"
	if got := hex.EncodeToString(k.clientKey); got != wantClientKey {
		t.Errorf("client key = %s, want %s", got, wantClientKey)
	}
	if got := hex.EncodeToString(k.clientIV); got != wantClientIV {
		t.Errorf("client iv = %s, want %s", got, wantClientIV)
	}
	if got := hex.EncodeToString(k.clientHP); got != wantClientHP {
		t.Errorf("client hp = %s, want %s", got, wantClientHP)
	}
}
