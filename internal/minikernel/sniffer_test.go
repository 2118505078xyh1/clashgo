package minikernel

import (
	"bufio"
	"bytes"
	"testing"
)

// buildTLSClientHello 构造一个带 SNI 扩展的最小 TLS ClientHello。
func buildTLSClientHello(sni string) []byte {
	var b bytes.Buffer
	// TLS record header: type=0x16, version, length 占位。
	b.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	// handshake header: type=0x01, length 占位。
	b.Write([]byte{0x01, 0x00, 0x00, 0x00})
	// client_version + random(32) + session_id_len=0
	b.Write([]byte{0x03, 0x03})
	b.Write(make([]byte, 32))
	b.WriteByte(0x00)
	// cipher_suites: len=2, one suite
	b.Write([]byte{0x00, 0x02, 0x13, 0x01})
	// compression methods: len=1, null
	b.Write([]byte{0x01, 0x00})
	// SNI extension: type=0x0000, len, list_len, name_type=0, name_len, name
	var sniExt bytes.Buffer
	sniExt.WriteByte(0x00) // name_type = host_name
	sniExt.WriteByte(byte(len(sni) >> 8))
	sniExt.WriteByte(byte(len(sni)))
	sniExt.WriteString(sni)
	var extData bytes.Buffer
	extData.WriteByte(byte(sniExt.Len() >> 8))
	extData.WriteByte(byte(sniExt.Len()))
	extData.Write(sniExt.Bytes())
	// 扩展块：type + length + data，前面加 extensions_total_length。
	var extBlock bytes.Buffer
	extBlock.Write([]byte{0x00, 0x00}) // ext type = server_name
	extBlock.WriteByte(byte(extData.Len() >> 8))
	extBlock.WriteByte(byte(extData.Len()))
	extBlock.Write(extData.Bytes())
	b.WriteByte(byte(extBlock.Len() >> 8))
	b.WriteByte(byte(extBlock.Len()))
	b.Write(extBlock.Bytes())

	out := b.Bytes()
	// 回填 record length（out[3:5]）和 handshake length（out[5:8]）。
	recLen := len(out) - 5
	out[3] = byte(recLen >> 8)
	out[4] = byte(recLen)
	hsLen := len(out) - 9
	out[6] = byte(hsLen >> 16)
	out[7] = byte(hsLen >> 8)
	out[8] = byte(hsLen)
	return out
}

func TestSniffTLS(t *testing.T) {
	data := buildTLSClientHello("www.example.com")
	r := bufio.NewReaderSize(bytes.NewReader(data), 64*1024)
	got := sniffHost(r)
	if got != "www.example.com" {
		t.Fatalf("sniffHost = %q, want www.example.com", got)
	}
	// 确认 Peek 不消耗数据。
	all, _ := r.Peek(len(data))
	if !bytes.Equal(all, data) {
		t.Error("Peek consumed data")
	}
}

func TestSniffHTTP(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: api.example.org:8080\r\nUser-Agent: test\r\n\r\n")
	r := bufio.NewReader(bytes.NewReader(data))
	got := sniffHost(r)
	if got != "api.example.org" {
		t.Fatalf("sniffHost = %q, want api.example.org", got)
	}
}

func TestSniffNoMatch(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{0x05, 0x01, 0x00}))
	if got := sniffHost(r); got != "" {
		t.Fatalf("sniffHost = %q, want empty", got)
	}
}
