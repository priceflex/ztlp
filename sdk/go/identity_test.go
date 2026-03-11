package ztlp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNodeIDGenerate(t *testing.T) {
	id1, err := GenerateNodeID()
	if err != nil {
		t.Fatalf("GenerateNodeID: %v", err)
	}
	id2, err := GenerateNodeID()
	if err != nil {
		t.Fatalf("GenerateNodeID: %v", err)
	}
	if id1 == id2 {
		t.Error("two random NodeIDs should differ")
	}
	if id1.IsZero() {
		t.Error("generated NodeID should not be zero")
	}
}

func TestNodeIDFromBytes(t *testing.T) {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(i)
	}
	id, err := NodeIDFromBytes(b)
	if err != nil {
		t.Fatalf("NodeIDFromBytes: %v", err)
	}
	for i := range b {
		if id[i] != b[i] {
			t.Errorf("byte %d: got %d, want %d", i, id[i], b[i])
		}
	}

	// Wrong length should fail
	_, err = NodeIDFromBytes([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestNodeIDFromHex(t *testing.T) {
	hexStr := "000102030405060708090a0b0c0d0e0f"
	id, err := NodeIDFromHex(hexStr)
	if err != nil {
		t.Fatalf("NodeIDFromHex: %v", err)
	}
	if id.String() != hexStr {
		t.Errorf("String() = %q, want %q", id.String(), hexStr)
	}

	// Invalid hex
	_, err = NodeIDFromHex("not-hex")
	if err == nil {
		t.Error("expected error for invalid hex")
	}

	// Wrong length
	_, err = NodeIDFromHex("0102")
	if err == nil {
		t.Error("expected error for short hex")
	}
}

func TestNodeIDJSON(t *testing.T) {
	id, _ := GenerateNodeID()

	data, err := json.Marshal(id)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var restored NodeID
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if id != restored {
		t.Errorf("got %v, want %v", restored, id)
	}
}

func TestGenerateIdentity(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if id.NodeID.IsZero() {
		t.Error("NodeID should not be zero")
	}
	if len(id.StaticPrivateKey) != 32 {
		t.Errorf("private key length: %d, want 32", len(id.StaticPrivateKey))
	}
	if len(id.StaticPublicKey) != 32 {
		t.Errorf("public key length: %d, want 32", len(id.StaticPublicKey))
	}
}

func TestIdentitySaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")

	orig, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	if err := orig.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Check file permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("permissions: %o, want 0600", perm)
	}

	loaded, err := LoadIdentity(path)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}

	if orig.NodeID != loaded.NodeID {
		t.Error("NodeID mismatch")
	}
	if string(orig.StaticPrivateKey) != string(loaded.StaticPrivateKey) {
		t.Error("StaticPrivateKey mismatch")
	}
	if string(orig.StaticPublicKey) != string(loaded.StaticPublicKey) {
		t.Error("StaticPublicKey mismatch")
	}
}

func TestLoadIdentityNotFound(t *testing.T) {
	_, err := LoadIdentity("/nonexistent/path.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestNodeIDZero(t *testing.T) {
	var zero NodeID
	if !zero.IsZero() {
		t.Error("zero NodeID should be zero")
	}
	id, _ := GenerateNodeID()
	if id.IsZero() {
		t.Error("random NodeID should not be zero (astronomically unlikely)")
	}
}
