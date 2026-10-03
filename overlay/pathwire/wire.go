// Package pathwire defines the bounded LAN/relay envelope. Keep the One and
// Gateway copies identical; cross-repository interoperability tests cover it.
package pathwire

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const MaxFrame = 8192
const RelayPort = 51821

type Frame struct {
	Type       string   `json:"type"`
	Network    string   `json:"network,omitempty"`
	From       string   `json:"from,omitempty"`
	To         string   `json:"to,omitempty"`
	Epoch      string   `json:"epoch,omitempty"`
	Seq        uint64   `json:"seq,omitempty"`
	Nonce      string   `json:"nonce,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
	Payload    []byte   `json:"payload,omitempty"`
	MAC        []byte   `json:"mac,omitempty"`
}

func Key(privateText, publicText, network, purpose string) ([]byte, error) {
	private, e := base64.StdEncoding.DecodeString(strings.TrimSpace(privateText))
	if e != nil {
		return nil, errors.New("invalid local key")
	}
	public, e := base64.StdEncoding.DecodeString(publicText)
	if e != nil {
		return nil, errors.New("invalid peer key")
	}
	priv, e := ecdh.X25519().NewPrivateKey(private)
	if e != nil {
		return nil, errors.New("invalid local key")
	}
	pub, e := ecdh.X25519().NewPublicKey(public)
	if e != nil {
		return nil, errors.New("invalid peer key")
	}
	shared, e := priv.ECDH(pub)
	if e != nil {
		return nil, errors.New("invalid peer key agreement")
	}
	h := hmac.New(sha256.New, shared)
	h.Write([]byte("xconnect-path-v1\x00" + network + "\x00" + purpose))
	return h.Sum(nil), nil
}
func Sign(f Frame, key []byte) Frame {
	f.MAC = nil
	b, _ := json.Marshal(f)
	h := hmac.New(sha256.New, key)
	h.Write(b)
	f.MAC = h.Sum(nil)
	return f
}
func Verify(f Frame, key []byte) bool {
	return len(f.MAC) == sha256.Size && hmac.Equal(f.MAC, Sign(f, key).MAC)
}
func Encode(f Frame) ([]byte, error) {
	b, e := json.Marshal(f)
	if e != nil || len(b) > MaxFrame {
		return nil, errors.New("oversized frame")
	}
	return b, nil
}
func Decode(b []byte) (Frame, error) {
	var f Frame
	if len(b) > MaxFrame {
		return f, errors.New("oversized frame")
	}
	e := json.Unmarshal(b, &f)
	return f, e
}
func Write(w io.Writer, f Frame) error {
	b, e := Encode(f)
	if e != nil {
		return e
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if e = writeAll(w, n[:]); e != nil {
		return e
	}
	return writeAll(w, b)
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func Read(r io.Reader) (Frame, error) {
	var f Frame
	var n [4]byte
	if _, e := io.ReadFull(r, n[:]); e != nil {
		return f, e
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > MaxFrame {
		return f, errors.New("invalid frame length")
	}
	b := make([]byte, int(size))
	if _, e := io.ReadFull(r, b); e != nil {
		return f, e
	}
	return Decode(b)
}

// LANHeader is fixed-size: at MTU 1280 the envelope + WG + IPv4 UDP
// remains below Ethernet MTU 1500. JSON/base64 is only used on relay streams.
const LANHeader = 122

func identity(s string) [16]byte {
	sum := sha256.Sum256([]byte(s))
	var r [16]byte
	copy(r[:], sum[:16])
	return r
}
func EncodeLAN(f Frame) ([]byte, error) {
	kind := byte(0)
	switch f.Type {
	case "data":
		kind = 1
	case "probe":
		kind = 2
	case "ack":
		kind = 3
	default:
		return nil, errors.New("invalid LAN frame")
	}
	epoch, e := hex.DecodeString(f.Epoch)
	if e != nil || len(epoch) != 16 || len(f.MAC) != 32 {
		return nil, errors.New("invalid LAN header")
	}
	if len(f.Payload) > 4096 {
		return nil, errors.New("oversized LAN payload")
	}
	b := make([]byte, LANHeader+len(f.Payload))
	b[0] = 1
	b[1] = kind
	for i, s := range []string{f.Network, f.From, f.To} {
		id := identity(s)
		copy(b[2+i*16:18+i*16], id[:])
	}
	copy(b[50:66], epoch)
	binary.BigEndian.PutUint64(b[66:74], f.Seq)
	if kind != 1 {
		nonce, e := hex.DecodeString(f.Nonce)
		if e != nil || len(nonce) != 16 {
			return nil, errors.New("invalid LAN nonce")
		}
		copy(b[74:90], nonce)
	}
	copy(b[90:122], f.MAC)
	copy(b[122:], f.Payload)
	return b, nil
}
func DecodeLAN(b []byte, network, self string, peers []string) (Frame, error) {
	var f Frame
	if len(b) < LANHeader || len(b) > LANHeader+4096 || b[0] != 1 {
		return f, errors.New("invalid LAN frame")
	}
	n, t := identity(network), identity(self)
	if !bytes.Equal(b[2:18], n[:]) || !bytes.Equal(b[34:50], t[:]) {
		return f, errors.New("LAN identity mismatch")
	}
	for _, id := range peers {
		h := identity(id)
		if bytes.Equal(b[18:34], h[:]) {
			f.From = id
			break
		}
	}
	if f.From == "" {
		return f, errors.New("unknown LAN peer")
	}
	f.Network = network
	f.To = self
	f.Epoch = hex.EncodeToString(b[50:66])
	f.Seq = binary.BigEndian.Uint64(b[66:74])
	f.MAC = append([]byte(nil), b[90:122]...)
	switch b[1] {
	case 1:
		f.Type = "data"
		f.Payload = append([]byte(nil), b[122:]...)
	case 2:
		f.Type = "probe"
		f.Nonce = hex.EncodeToString(b[74:90])
	case 3:
		f.Type = "ack"
		f.Nonce = hex.EncodeToString(b[74:90])
	default:
		return f, errors.New("invalid LAN type")
	}
	if b[1] != 1 && len(b) != LANHeader {
		return f, errors.New("unexpected LAN payload")
	}
	return f, nil
}
