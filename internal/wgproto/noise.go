package wgproto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"
)

// Noise_IKpsk2 常量（WireGuard 白皮书 §5.4）。
var (
	noiseConstruction = []byte("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
	noiseIdentifier   = []byte("WireGuard v1 zx2c4 Jason@zx2c4.com")
	noiseLabelMAC1    = []byte("mac1----")
	zeroPSK           [32]byte // 本实现不使用预共享密钥，PSK 全零
)

const (
	messageInitiationType = 1
	messageResponseType   = 2
	messageTransportType  = 4

	messageInitiationSize = 148
	messageResponseSize   = 92
	transportHeaderSize   = 16
	aeadTagSize           = 16
)

var (
	errBadResponseLength = errors.New("wgproto: bad handshake response length")
	errBadResponseType   = errors.New("wgproto: bad handshake response type")
	errWrongReceiver     = errors.New("wgproto: handshake response has wrong receiver index")
	errResponseAuth      = errors.New("wgproto: handshake response authentication failed")
)

// noiseHandshake 保存发起方一次握手的中间状态。
type noiseHandshake struct {
	chainKey    [blake2sSize]byte
	hash        [blake2sSize]byte
	ephemeral   *ecdh.PrivateKey
	localIndex  uint32
	remoteIndex uint32
}

// newNoiseHandshake 初始化 C = HASH(CONSTRUCTION), H = HASH(C || IDENTIFIER)，
// 并把响应方静态公钥混入 H（pre-message <- s）。
func newNoiseHandshake(peerStatic []byte, localIndex uint32) (*noiseHandshake, error) {
	ck := blake2sSum256(noiseConstruction)
	h := ck
	mixHash(&h, noiseIdentifier)
	mixHash(&h, peerStatic)
	return &noiseHandshake{chainKey: ck, hash: h, localIndex: localIndex}, nil
}

func aeadSeal(key *[blake2sSize]byte, plaintext, ad []byte) ([]byte, error) {
	aead, err := newChaCha20Poly1305(key[:])
	if err != nil {
		return nil, err
	}
	var zero [12]byte
	return aead.Seal(nil, zero[:], plaintext, ad), nil
}

func aeadOpen(key *[blake2sSize]byte, ciphertext, ad []byte) ([]byte, error) {
	aead, err := newChaCha20Poly1305(key[:])
	if err != nil {
		return nil, err
	}
	var zero [12]byte
	return aead.Open(nil, zero[:], ciphertext, ad)
}

func tai64nNow() [12]byte {
	var ts [12]byte
	now := time.Now()
	binary.BigEndian.PutUint64(ts[0:8], uint64(now.Unix()))
	binary.BigEndian.PutUint32(ts[8:12], uint32(now.Nanosecond()))
	return ts
}

// createInitiation 构造 148 字节的握手发起消息。
func (hs *noiseHandshake) createInitiation(localStatic *ecdh.PrivateKey, peerStatic []byte) ([]byte, error) {
	curve := ecdh.X25519()
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	hs.ephemeral = ephemeral
	ephemeralPub := ephemeral.PublicKey().Bytes()

	peerPub, err := curve.NewPublicKey(peerStatic)
	if err != nil {
		return nil, err
	}

	// E_pub 混入 key 与 hash
	mixKey(&hs.chainKey, ephemeralPub)
	mixHash(&hs.hash, ephemeralPub)

	// es: DH(E_priv_i, S_pub_r) -> 加密静态公钥
	ss, err := ephemeral.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	var ck, key [blake2sSize]byte
	kdf2(&ck, &key, hs.chainKey[:], ss)
	hs.chainKey = ck
	localPub := localStatic.PublicKey().Bytes()
	encStatic, err := aeadSeal(&key, localPub, hs.hash[:])
	if err != nil {
		return nil, err
	}
	mixHash(&hs.hash, encStatic)

	// ss: DH(S_priv_i, S_pub_r) -> 加密时间戳
	ss, err = localStatic.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	kdf2(&ck, &key, hs.chainKey[:], ss)
	hs.chainKey = ck
	ts := tai64nNow()
	encTS, err := aeadSeal(&key, ts[:], hs.hash[:])
	if err != nil {
		return nil, err
	}
	mixHash(&hs.hash, encTS)

	msg := make([]byte, messageInitiationSize)
	binary.LittleEndian.PutUint32(msg[0:4], messageInitiationType)
	binary.LittleEndian.PutUint32(msg[4:8], hs.localIndex)
	copy(msg[8:40], ephemeralPub)
	copy(msg[40:88], encStatic) // 32+16 = 48
	copy(msg[88:116], encTS)    // 12+16 = 28

	// mac1 = MAC(HASH(LABEL_MAC1 || S_pub_r), msg[0:116])；mac2 保持全零。
	var macKeyInput [8 + 32]byte
	copy(macKeyInput[:8], noiseLabelMAC1)
	copy(macKeyInput[8:], peerStatic)
	macKey := blake2sSum256(macKeyInput[:])
	mac1 := blake2sMAC(macKey[:], msg[:116], blake2sSize128)
	copy(msg[116:132], mac1)

	return msg, nil
}

// consumeResponse 校验 92 字节响应消息，完成 ee / se / psk 的密钥派生，
// 返回 (sendKey, recvKey)（发起方视角）。
func (hs *noiseHandshake) consumeResponse(msg []byte, localStatic *ecdh.PrivateKey) (sendKey, recvKey [blake2sSize]byte, err error) {
	if len(msg) != messageResponseSize {
		err = errBadResponseLength
		return
	}
	if binary.LittleEndian.Uint32(msg[0:4]) != messageResponseType {
		err = errBadResponseType
		return
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != hs.localIndex {
		err = errWrongReceiver
		return
	}
	if hs.ephemeral == nil {
		err = errors.New("wgproto: no ephemeral key in handshake")
		return
	}

	curve := ecdh.X25519()
	remoteEphemeral, err := curve.NewPublicKey(msg[12:44])
	if err != nil {
		return
	}

	mixHash(&hs.hash, msg[12:44])
	mixKey(&hs.chainKey, msg[12:44])

	// ee: DH(E_priv_i, E_pub_r)
	ss, err := hs.ephemeral.ECDH(remoteEphemeral)
	if err != nil {
		return
	}
	mixKey(&hs.chainKey, ss)
	// se: DH(S_priv_i, E_pub_r)
	ss, err = localStatic.ECDH(remoteEphemeral)
	if err != nil {
		return
	}
	mixKey(&hs.chainKey, ss)

	// psk2: (C, tau, key) = KDF3(C, Q)
	var ck, tau, key [blake2sSize]byte
	kdf3(&ck, &tau, &key, hs.chainKey[:], zeroPSK[:])
	hs.chainKey = ck
	mixHash(&hs.hash, tau[:])

	if _, err = aeadOpen(&key, msg[44:60], hs.hash[:]); err != nil {
		err = errResponseAuth
		return
	}
	mixHash(&hs.hash, msg[44:60])

	// 发起方：KDF2(C, nil) -> (send, recv)
	kdf2(&sendKey, &recvKey, hs.chainKey[:], nil)
	hs.remoteIndex = binary.LittleEndian.Uint32(msg[4:8])
	return
}
