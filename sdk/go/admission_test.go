package ztlp

import (
	"encoding/hex"
	"testing"
)

func TestHMACBLAKE2sDeterministic(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0xAA
	}
	message := []byte("hello world")

	mac1 := HMACBLAKE2s(key, message)
	mac2 := HMACBLAKE2s(key, message)

	if mac1 != mac2 {
		t.Error("same inputs should produce same MAC")
	}

	// Different key → different MAC
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = 0xBB
	}
	mac3 := HMACBLAKE2s(key2, message)
	if mac1 == mac3 {
		t.Error("different key should produce different MAC")
	}

	// Different message → different MAC
	mac4 := HMACBLAKE2s(key, []byte("hello worlD"))
	if mac1 == mac4 {
		t.Error("different message should produce different MAC")
	}
}

func TestHMACBLAKE2sLongKey(t *testing.T) {
	longKey := make([]byte, 128) // longer than 64-byte block size
	for i := range longKey {
		longKey[i] = 0xCC
	}
	mac := HMACBLAKE2s(longKey, []byte("test"))

	if mac == [32]byte{} {
		t.Error("MAC should not be all zeros")
	}

	// Consistent with itself
	mac2 := HMACBLAKE2s(longKey, []byte("test"))
	if mac != mac2 {
		t.Error("same inputs should produce same MAC")
	}
}

func TestHMACBLAKE2sEmptyMessage(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x42
	}
	mac := HMACBLAKE2s(key, []byte{})
	if mac == [32]byte{} {
		t.Error("MAC should not be all zeros")
	}
}

func TestHMACBLAKE2sEmptyKey(t *testing.T) {
	mac := HMACBLAKE2s([]byte{}, []byte("test message"))
	if mac == [32]byte{} {
		t.Error("MAC should not be all zeros")
	}
}

func TestRATRoundtrip(t *testing.T) {
	secret := [32]byte{0x42}
	nodeID := [16]byte{0x11}
	issuerID := [16]byte{0x22}
	scope := [12]byte{}

	token := IssueRAT(nodeID, issuerID, scope, 300, &secret)

	serialized := token.Serialize()
	if len(serialized) != RATSize {
		t.Fatalf("serialized size: %d, want %d", len(serialized), RATSize)
	}

	parsed, err := ParseRAT(serialized[:])
	if err != nil {
		t.Fatalf("ParseRAT: %v", err)
	}

	if !parsed.Verify(&secret) {
		t.Error("parsed token should verify")
	}
	if parsed.IsExpired() {
		t.Error("fresh token should not be expired")
	}
	if parsed.Version != RATVersion {
		t.Errorf("version: %d, want %d", parsed.Version, RATVersion)
	}
	if parsed.NodeID != nodeID {
		t.Error("nodeID mismatch")
	}
	if parsed.IssuerID != issuerID {
		t.Error("issuerID mismatch")
	}
}

func TestRATExpired(t *testing.T) {
	secret := [32]byte{0x42}
	nodeID := [16]byte{0x11}
	issuerID := [16]byte{0x22}

	// Issue a token that expired in the past
	token := IssueRATAt(nodeID, issuerID, [12]byte{}, 1000000, 1000010, &secret)

	if !token.Verify(&secret) {
		t.Error("MAC should still be valid even for expired token")
	}
	if !token.IsExpired() {
		t.Error("token should be expired")
	}
	if token.TTLSeconds() != 0 {
		t.Errorf("TTL: %d, want 0", token.TTLSeconds())
	}
}

func TestRATSessionScope(t *testing.T) {
	secret := [32]byte{0x42}
	nodeID := [16]byte{0x11}
	issuerID := [16]byte{0x22}

	// Any-session scope
	anyToken := IssueRAT(nodeID, issuerID, [12]byte{}, 300, &secret)
	if !anyToken.ValidForSession([12]byte{0xFF}) {
		t.Error("any-scope token should be valid for any session")
	}

	// Specific scope
	specificScope := [12]byte{0xAA}
	scopedToken := IssueRAT(nodeID, issuerID, specificScope, 300, &secret)
	if !scopedToken.ValidForSession(specificScope) {
		t.Error("scoped token should be valid for matching session")
	}
	if scopedToken.ValidForSession([12]byte{0xBB}) {
		t.Error("scoped token should not be valid for different session")
	}
}

func TestRATTamperedRejected(t *testing.T) {
	secret := [32]byte{0x42}
	nodeID := [16]byte{0x11}
	issuerID := [16]byte{0x22}

	token := IssueRAT(nodeID, issuerID, [12]byte{}, 300, &secret)

	// Tamper with nodeID
	serialized := token.Serialize()
	serialized[1] ^= 0xFF
	tampered, _ := ParseRAT(serialized[:])
	if tampered.Verify(&secret) {
		t.Error("tampered nodeID should fail verification")
	}

	// Tamper with expiresAt
	serialized2 := token.Serialize()
	serialized2[41] ^= 0xFF
	tampered2, _ := ParseRAT(serialized2[:])
	if tampered2.Verify(&secret) {
		t.Error("tampered expiresAt should fail verification")
	}

	// Tamper with MAC
	serialized3 := token.Serialize()
	serialized3[61] ^= 0xFF
	tampered3, _ := ParseRAT(serialized3[:])
	if tampered3.Verify(&secret) {
		t.Error("tampered MAC should fail verification")
	}
}

func TestRATWrongSecret(t *testing.T) {
	secret := [32]byte{0x42}
	wrongSecret := [32]byte{0x99}

	token := IssueRAT([16]byte{0x11}, [16]byte{0x22}, [12]byte{}, 300, &secret)

	if !token.Verify(&secret) {
		t.Error("correct secret should verify")
	}
	if token.Verify(&wrongSecret) {
		t.Error("wrong secret should not verify")
	}
}

func TestRATInvalidSize(t *testing.T) {
	_, err := ParseRAT([]byte{})
	if err == nil {
		t.Error("expected error for empty data")
	}
	_, err = ParseRAT(make([]byte, 92))
	if err == nil {
		t.Error("expected error for 92 bytes")
	}
	_, err = ParseRAT(make([]byte, 94))
	if err == nil {
		t.Error("expected error for 94 bytes")
	}
}

func TestRATDisplay(t *testing.T) {
	secret := [32]byte{0x42}
	token := IssueRAT([16]byte{0x11}, [16]byte{0x22}, [12]byte{}, 300, &secret)
	display := token.Display()
	if len(display) == 0 {
		t.Error("display should not be empty")
	}
	// Should contain recognizable parts
	if !containsStr(display, "RAT v1") {
		t.Error("display should contain version")
	}
	if !containsStr(display, hex.EncodeToString(token.NodeID[:])) {
		t.Error("display should contain nodeID")
	}
}

func TestRATTTLSeconds(t *testing.T) {
	secret := [32]byte{0x42}
	token := IssueRAT([16]byte{0x11}, [16]byte{0x22}, [12]byte{}, 300, &secret)

	ttl := token.TTLSeconds()
	if ttl > 300 || ttl < 298 {
		t.Errorf("TTL: %d, expected ~300", ttl)
	}
}

func TestHandshakeExtensionRoundtrip(t *testing.T) {
	secret := [32]byte{0x42}
	token := IssueRAT([16]byte{0x11}, [16]byte{0x22}, [12]byte{}, 300, &secret)

	ext := &HandshakeExtension{Token: token}
	data := ext.SerializeExtension()
	if len(data) != 1+RATSize {
		t.Errorf("extension size: %d, want %d", len(data), 1+RATSize)
	}
	if data[0] != ExtTypeRAT {
		t.Errorf("ext type: 0x%02X, want 0x%02X", data[0], ExtTypeRAT)
	}

	parsed, err := ParseHandshakeExtension(data)
	if err != nil {
		t.Fatalf("ParseHandshakeExtension: %v", err)
	}
	if parsed.Token == nil {
		t.Fatal("parsed token should not be nil")
	}
	if parsed.Token.NodeID != token.NodeID {
		t.Error("nodeID mismatch")
	}
	if !parsed.Token.Verify(&secret) {
		t.Error("parsed token should verify")
	}
}

func TestHandshakeExtensionWireLen(t *testing.T) {
	secret := [32]byte{0x42}
	token := IssueRAT([16]byte{0x11}, [16]byte{0x22}, [12]byte{}, 300, &secret)
	ext := &HandshakeExtension{Token: token}
	if ext.WireLen() != 94 {
		t.Errorf("wire len: %d, want 94", ext.WireLen())
	}
}

func TestCrossLanguageKnownVector(t *testing.T) {
	// Same test vector as the Rust test_cross_language_known_vector
	secret := [32]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}

	nodeID := [16]byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}
	issuerID := [16]byte{0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
		0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB}
	issuedAt := uint64(1700000000)
	expiresAt := uint64(1700000300)
	sessionScope := [12]byte{} // any session

	token := IssueRATAt(nodeID, issuerID, sessionScope, issuedAt, expiresAt, &secret)

	if token.Version != RATVersion {
		t.Errorf("version: %d, want %d", token.Version, RATVersion)
	}
	if token.NodeID != nodeID {
		t.Error("nodeID mismatch")
	}
	if token.IssuerID != issuerID {
		t.Error("issuerID mismatch")
	}
	if token.IssuedAt != issuedAt {
		t.Errorf("issuedAt: %d, want %d", token.IssuedAt, issuedAt)
	}
	if token.ExpiresAt != expiresAt {
		t.Errorf("expiresAt: %d, want %d", token.ExpiresAt, expiresAt)
	}
	if !token.Verify(&secret) {
		t.Error("token should verify with correct secret")
	}

	// Serialize, parse, verify again
	serialized := token.Serialize()
	if len(serialized) != RATSize {
		t.Fatalf("serialized size: %d", len(serialized))
	}
	parsed, err := ParseRAT(serialized[:])
	if err != nil {
		t.Fatalf("ParseRAT: %v", err)
	}
	if parsed.MAC != token.MAC {
		t.Error("MAC mismatch after roundtrip")
	}
	if !parsed.Verify(&secret) {
		t.Error("parsed token should verify")
	}

	t.Logf("Cross-language test vector:")
	t.Logf("  Secret: %s", hex.EncodeToString(secret[:]))
	t.Logf("  Token:  %s", hex.EncodeToString(serialized[:]))
	t.Logf("  MAC:    %s", hex.EncodeToString(token.MAC[:]))
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
