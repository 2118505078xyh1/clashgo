package quicproto

// QUIC transport parameters (RFC 9000 §18.2) encoded as TLV.  crypto/tls
// treats transport parameters as opaque bytes, so this is the only place
// where they are built or parsed.

import "fmt"

// Transport parameter IDs.
const (
	tpOriginalDestinationConnectionID = 0x00
	tpMaxIdleTimeout                  = 0x01
	tpStatelessResetToken             = 0x02
	tpMaxUDPPayloadSize               = 0x03
	tpInitialMaxData                  = 0x04
	tpInitialMaxStreamDataBidiLocal   = 0x05
	tpInitialMaxStreamDataBidiRemote  = 0x06
	tpInitialMaxStreamDataUni         = 0x07
	tpInitialMaxStreamsBidi           = 0x08
	tpInitialMaxStreamsUni            = 0x09
	tpAckDelayExponent                = 0x0a
	tpMaxAckDelay                     = 0x0b
	tpDisableActiveMigration          = 0x0c
	tpActiveConnectionIDLimit         = 0x0e
	tpInitialSourceConnectionID       = 0x0f
	tpRetrySourceConnectionID         = 0x10
)

const (
	clientMaxUDPPayloadSize = 65527
	clientInitialMaxData    = 1 << 20 // 1 MiB
	clientStreamDataLimit   = 1 << 20
	clientMaxStreams        = 100
	// max_idle_timeout=30s（毫秒）：避免服务端把 0 clamp 成 5s 导致早关。
	clientMaxIdleTimeout = 30000
	// max_datagram_frame_size：声明支持 DATAGRAM（Hysteria2/HTTP3 需要，
	// 否则发 DATAGRAM 会触发 PROTOCOL_VIOLATION 0xa）。
	clientMaxDatagramFrameSize = 65535
)

type transportParameters struct {
	originalDestinationConnectionID []byte
	initialSourceConnectionID       []byte
	maxUDPPayloadSize               uint64
	initialMaxData                  uint64
	initialMaxStreamDataBidiLocal   uint64
	initialMaxStreamDataBidiRemote  uint64
	initialMaxStreamDataUni         uint64
	initialMaxStreamsBidi           uint64
	initialMaxStreamsUni            uint64
	maxIdleTimeout                  uint64
}

func appendTLV(b []byte, id uint64, value []byte) []byte {
	b = appendVarint(b, id)
	b = appendVarint(b, uint64(len(value)))
	return append(b, value...)
}

func appendVarintTLV(b []byte, id, value uint64) []byte {
	return appendTLV(b, id, appendVarint(nil, value))
}

// encodeClientTransportParameters builds a valid client transport parameter
// block.  scid must equal the Source Connection ID of the client's Initial
// packet (RFC 9000 §18.2 must set initial_source_connection_id).
func encodeClientTransportParameters(scid []byte) []byte {
	b := make([]byte, 0, 128)
	b = appendVarintTLV(b, tpMaxIdleTimeout, clientMaxIdleTimeout)
	b = appendVarintTLV(b, tpMaxUDPPayloadSize, clientMaxUDPPayloadSize)
	b = appendVarintTLV(b, tpInitialMaxData, clientInitialMaxData)
	b = appendVarintTLV(b, tpInitialMaxStreamDataBidiLocal, clientStreamDataLimit)
	b = appendVarintTLV(b, tpInitialMaxStreamDataBidiRemote, clientStreamDataLimit)
	b = appendVarintTLV(b, tpInitialMaxStreamDataUni, clientStreamDataLimit)
	b = appendVarintTLV(b, tpInitialMaxStreamsBidi, clientMaxStreams)
	b = appendVarintTLV(b, tpInitialMaxStreamsUni, clientMaxStreams)
	b = appendTLV(b, tpInitialSourceConnectionID, scid)
	// active_connection_id_limit=4（quic-go 客户端默认值，对齐以便拿到更多 CID）。
	b = appendVarintTLV(b, tpActiveConnectionIDLimit, 4)
	// max_datagram_frame_size：声明 DATAGRAM 支持（RFC 9221 参数 ID 0x20）。
	b = appendVarintTLV(b, 0x20, clientMaxDatagramFrameSize)
	return b
}

// encodeServerTransportParameters is used by the local test server.
func encodeServerTransportParameters(scid, originalDCID []byte) []byte {
	b := make([]byte, 0, 128)
	b = appendTLV(b, tpOriginalDestinationConnectionID, originalDCID)
	b = appendVarintTLV(b, tpMaxUDPPayloadSize, 65535)
	b = appendVarintTLV(b, tpInitialMaxData, clientInitialMaxData)
	b = appendVarintTLV(b, tpInitialMaxStreamDataBidiLocal, clientStreamDataLimit)
	b = appendVarintTLV(b, tpInitialMaxStreamDataBidiRemote, clientStreamDataLimit)
	b = appendVarintTLV(b, tpInitialMaxStreamDataUni, clientStreamDataLimit)
	b = appendVarintTLV(b, tpInitialMaxStreamsBidi, clientMaxStreams)
	b = appendVarintTLV(b, tpInitialMaxStreamsUni, clientMaxStreams)
	b = appendTLV(b, tpInitialSourceConnectionID, scid)
	return b
}

// parseTransportParameters decodes a transport parameter block.  Unknown IDs
// are skipped, as required by RFC 9000 §18.2.
func parseTransportParameters(b []byte) (*transportParameters, error) {
	tp := &transportParameters{}
	for len(b) > 0 {
		id, n, err := readVarint(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		length, n, err := readVarint(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		if uint64(len(b)) < length {
			return nil, fmt.Errorf("quicproto: truncated transport parameter 0x%x", id)
		}
		value := b[:length]
		b = b[length:]
		switch id {
		case tpOriginalDestinationConnectionID:
			tp.originalDestinationConnectionID = append([]byte(nil), value...)
		case tpInitialSourceConnectionID:
			tp.initialSourceConnectionID = append([]byte(nil), value...)
		case tpMaxUDPPayloadSize:
			tp.maxUDPPayloadSize, _, err = readVarint(value)
			if err != nil {
				return nil, err
			}
		case tpInitialMaxData:
			tp.initialMaxData, _, err = readVarint(value)
			if err != nil {
				return nil, err
			}
		case tpInitialMaxStreamDataBidiLocal:
			tp.initialMaxStreamDataBidiLocal, _, err = readVarint(value)
			if err != nil {
				return nil, err
			}
		case tpInitialMaxStreamDataBidiRemote:
			tp.initialMaxStreamDataBidiRemote, _, err = readVarint(value)
			if err != nil {
				return nil, err
			}
		case tpInitialMaxStreamDataUni:
			tp.initialMaxStreamDataUni, _, err = readVarint(value)
			if err != nil {
				return nil, err
			}
		case tpInitialMaxStreamsBidi:
			tp.initialMaxStreamsBidi, _, err = readVarint(value)
			if err != nil {
				return nil, err
			}
		case tpInitialMaxStreamsUni:
			tp.initialMaxStreamsUni, _, err = readVarint(value)
			if err != nil {
				return nil, err
			}
		case tpMaxIdleTimeout:
			tp.maxIdleTimeout, _, err = readVarint(value)
			if err != nil {
				return nil, err
			}
		}
	}
	return tp, nil
}
