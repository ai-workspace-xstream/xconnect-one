package runtime

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestDeriveWireGuardPublicKey(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())
	wantPub := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())

	got, err := deriveWireGuardPublicKey(privB64)
	if err != nil {
		t.Fatalf("deriveWireGuardPublicKey error: %v", err)
	}
	if got != wantPub {
		t.Fatalf("got=%q want=%q", got, wantPub)
	}

	if _, err := deriveWireGuardPublicKey("not-valid-base64"); err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestParseWireGuardHandshakes(t *testing.T) {
	out := "peerA=\t0\npeerB=\t1700000100\npeerC=\t1700000250\nbadline\n"
	got := parseWireGuardHandshakes(out)
	want := time.Unix(1700000250, 0).UTC()
	if !got.Equal(want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
	if !parseWireGuardHandshakes("peerA=\t0\n").IsZero() {
		t.Fatal("expected zero time for zero handshake")
	}
}

func TestParseWireGuardTransfer(t *testing.T) {
	out := "peerA=\t1200\t3400\npeerB=\t800\t600\n"
	rx, tx := parseWireGuardTransfer(out)
	if rx != 2000 || tx != 4000 {
		t.Fatalf("rx=%d tx=%d want 2000/4000", rx, tx)
	}
}

func TestExtractPrimaryPeerPublicKey(t *testing.T) {
	cfg := `
[Interface]
PrivateKey = AAAA
PublicKey = BBBB

[Peer]
PublicKey = peerKey1==
Endpoint = 127.0.0.1:51830

[Peer]
PublicKey = peerKey2==
`
	if got := extractPrimaryPeerPublicKey(cfg); got != "peerKey1==" {
		t.Fatalf("got=%q want=%q", got, "peerKey1==")
	}
}
