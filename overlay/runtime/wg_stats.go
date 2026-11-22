package runtime

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

// deriveWireGuardPublicKey derives the Curve25519 public key from a base64-encoded
// 32-byte WireGuard private key using the standard library X25519 implementation.
func deriveWireGuardPublicKey(privateKeyB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKeyB64))
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid WireGuard private key")
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// parseWireGuardHandshakes parses `wg show <iface> latest-handshakes` output and
// returns the newest non-zero UTC handshake timestamp.
func parseWireGuardHandshakes(output string) time.Time {
	var newest int64
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		sec, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
		if err != nil || sec <= 0 {
			continue
		}
		if sec > newest {
			newest = sec
		}
	}
	if newest <= 0 {
		return time.Time{}
	}
	return time.Unix(newest, 0).UTC()
}

// parseWireGuardTransfer parses `wg show <iface> transfer` output and sums
// received and transmitted bytes across all peers.
func parseWireGuardTransfer(output string) (rx uint64, tx uint64) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		peerRx, errRx := strconv.ParseUint(fields[len(fields)-2], 10, 64)
		peerTx, errTx := strconv.ParseUint(fields[len(fields)-1], 10, 64)
		if errRx != nil || errTx != nil {
			continue
		}
		rx += peerRx
		tx += peerTx
	}
	return rx, tx
}

// extractPrimaryPeerPublicKey extracts the first [Peer] block's PublicKey value
// from a rendered WireGuard configuration file.
func extractPrimaryPeerPublicKey(wgConfig string) string {
	inPeer := false
	for _, rawLine := range strings.Split(wgConfig, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inPeer = strings.EqualFold(line, "[Peer]")
			continue
		}
		if !inPeer {
			continue
		}
		if eq := strings.IndexByte(line, '='); eq > 0 {
			key := strings.TrimSpace(line[:eq])
			val := strings.TrimSpace(line[eq+1:])
			if strings.EqualFold(key, "PublicKey") {
				return val
			}
		}
	}
	return ""
}
