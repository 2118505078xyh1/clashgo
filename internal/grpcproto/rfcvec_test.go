package grpcproto

import (
	"encoding/hex"
	"testing"
)

func TestHPACKRFCVectors(t *testing.T) {
	// RFC 7541 Appendix C.2.1 — 无 Huffman 的索引 + 字面量。
	fields := []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/"},
		{Name: ":authority", Value: "www.example.com"},
	}
	want := "828684410f7777772e6578616d706c652e636f6d"
	got := hex.EncodeToString(EncodeHeaders(fields))
	if got != want {
		t.Fatalf("RFC C.2.1: got %s, want %s", got, want)
	}
	raw, _ := hex.DecodeString(want)
	decoded, err := DecodeHeaders(raw)
	if err != nil {
		t.Fatalf("decode RFC C.2.1: %v", err)
	}
	if len(decoded) != 4 || decoded[3].Value != "www.example.com" {
		t.Fatalf("decoded RFC C.2.1 = %v", decoded)
	}

	// RFC 7541 Appendix C.2.3 — 自定义头（literal without indexing, 新名字）。
	fields2 := []HeaderField{
		{Name: "custom-key", Value: "custom-value"},
	}
	want2 := "000a637573746f6d2d6b65790c637573746f6d2d76616c7565"
	got2 := hex.EncodeToString(EncodeHeaders(fields2))
	if got2 != want2 {
		t.Fatalf("RFC C.2.3: got %s, want %s", got2, want2)
	}
	raw2, _ := hex.DecodeString(want2)
	decoded2, err := DecodeHeaders(raw2)
	if err != nil || len(decoded2) != 1 || decoded2[0].Name != "custom-key" || decoded2[0].Value != "custom-value" {
		t.Fatalf("decode RFC C.2.3 = %v, %v", decoded2, err)
	}
}
