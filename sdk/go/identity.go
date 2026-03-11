package ztlp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/flynn/noise"
)

// NodeID is a 128-bit (16-byte) random identifier for a ZTLP node.
// NodeIDs are NOT derived from public keys — they are randomly generated
// at enrollment time.
type NodeID [NodeIDSize]byte

// GenerateNodeID creates a new random 128-bit NodeID.
func GenerateNodeID() (NodeID, error) {
	var id NodeID
	if _, err := rand.Read(id[:]); err != nil {
		return id, fmt.Errorf("ztlp: generate NodeID: %w", err)
	}
	return id, nil
}

// NodeIDFromBytes creates a NodeID from a raw byte slice.
// Returns an error if the slice is not exactly 16 bytes.
func NodeIDFromBytes(b []byte) (NodeID, error) {
	var id NodeID
	if len(b) != NodeIDSize {
		return id, fmt.Errorf("ztlp: NodeID must be %d bytes, got %d", NodeIDSize, len(b))
	}
	copy(id[:], b)
	return id, nil
}

// NodeIDFromHex parses a hex-encoded NodeID string.
func NodeIDFromHex(s string) (NodeID, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return NodeID{}, fmt.Errorf("ztlp: invalid NodeID hex: %w", err)
	}
	return NodeIDFromBytes(b)
}

// IsZero returns true if the NodeID is all zeros.
func (n NodeID) IsZero() bool {
	return n == NodeID{}
}

// String returns the hex representation of the NodeID.
func (n NodeID) String() string {
	return hex.EncodeToString(n[:])
}

// Bytes returns the raw byte slice.
func (n NodeID) Bytes() []byte {
	return n[:]
}

// MarshalJSON implements json.Marshaler, encoding as a hex string.
func (n NodeID) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.String())
}

// UnmarshalJSON implements json.Unmarshaler, decoding from a hex string.
func (n *NodeID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := NodeIDFromHex(s)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// Identity represents a ZTLP node identity with cryptographic keys.
// This mirrors the Rust NodeIdentity struct.
type Identity struct {
	// NodeID is the stable 128-bit node identifier.
	NodeID NodeID `json:"node_id"`

	// StaticPrivateKey is the X25519 private key (32 bytes) for Noise_XX.
	StaticPrivateKey []byte `json:"static_private_key"`

	// StaticPublicKey is the X25519 public key (32 bytes).
	StaticPublicKey []byte `json:"static_public_key"`
}

// GenerateIdentity creates a new identity with a random NodeID and X25519 keypair.
// The keypair is generated using the flynn/noise library for compatibility
// with the Noise_XX handshake.
func GenerateIdentity() (*Identity, error) {
	nodeID, err := GenerateNodeID()
	if err != nil {
		return nil, err
	}

	// Generate X25519 keypair using the noise library (same approach as the Rust
	// implementation which uses snow's key generation).
	dh := noise.DH25519
	kp, err := dh.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ztlp: generate keypair: %w", err)
	}

	return &Identity{
		NodeID:           nodeID,
		StaticPrivateKey: kp.Private,
		StaticPublicKey:  kp.Public,
	}, nil
}

// LoadIdentity reads an identity from a JSON file.
// The format is compatible with the Rust implementation's identity files.
func LoadIdentity(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ztlp: load identity: %w", err)
	}

	// Parse the JSON using hex-encoded bytes (matching Rust's serde format)
	var raw struct {
		NodeID           string `json:"node_id"`
		StaticPrivateKey string `json:"static_private_key"`
		StaticPublicKey  string `json:"static_public_key"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("ztlp: parse identity JSON: %w", err)
	}

	nodeID, err := NodeIDFromHex(raw.NodeID)
	if err != nil {
		return nil, err
	}

	privKey, err := hex.DecodeString(raw.StaticPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ztlp: decode private key: %w", err)
	}

	pubKey, err := hex.DecodeString(raw.StaticPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ztlp: decode public key: %w", err)
	}

	return &Identity{
		NodeID:           nodeID,
		StaticPrivateKey: privKey,
		StaticPublicKey:  pubKey,
	}, nil
}

// Save writes the identity to a JSON file in the same format as the Rust
// implementation (hex-encoded byte fields).
func (id *Identity) Save(path string) error {
	raw := struct {
		NodeID           string `json:"node_id"`
		StaticPrivateKey string `json:"static_private_key"`
		StaticPublicKey  string `json:"static_public_key"`
	}{
		NodeID:           id.NodeID.String(),
		StaticPrivateKey: hex.EncodeToString(id.StaticPrivateKey),
		StaticPublicKey:  hex.EncodeToString(id.StaticPublicKey),
	}

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("ztlp: marshal identity: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("ztlp: save identity: %w", err)
	}
	return nil
}
