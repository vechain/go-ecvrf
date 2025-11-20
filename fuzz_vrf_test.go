package ecvrf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// deriveSecp256k1Key deterministically maps arbitrary bytes to a valid secp256k1 private key.
// d = (seed % (N-1)) + 1 to ensure 1 <= d < N
func deriveSecp256k1Key(seed []byte) *ecdsa.PrivateKey {
	if len(seed) == 0 {
		return nil
	}
	curve := secp256k1.S256()
	q := curve.Params().N
	d := new(big.Int).SetBytes(seed)
	d.Mod(d, new(big.Int).Sub(q, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	sk := secp256k1.PrivKeyFromBytes(d.Bytes())
	return sk.ToECDSA()
}

// deriveP256Key deterministically maps arbitrary bytes to a valid P-256 private key.
// d = (seed % (N-1)) + 1 to ensure 1 <= d < N
func deriveP256Key(seed []byte) *ecdsa.PrivateKey {
	if len(seed) == 0 {
		return nil
	}
	curve := elliptic.P256()
	q := curve.Params().N
	d := new(big.Int).SetBytes(seed)
	d.Mod(d, new(big.Int).Sub(q, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	x, y := curve.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}
}

func FuzzProveVerifySecp256k1(f *testing.F) {
	// Seed with a simple example
	f.Add([]byte("Hello VeChain"), []byte{1})
	f.Add([]byte{0x00, 0x01, 0x02}, []byte{0xFF, 0x00, 0xAA})

	f.Fuzz(func(t *testing.T, alpha []byte, skSeed []byte) {
		sk := deriveSecp256k1Key(skSeed)
		if sk == nil {
			t.Skip()
		}

		vrf := Secp256k1Sha256Tai

		beta1, pi, err := vrf.Prove(sk, alpha)
		if err != nil {
			// Not all inputs must be valid; just ensure no panic and continue.
			return
		}

		beta2, err := vrf.Verify(&sk.PublicKey, alpha, pi)
		if err != nil {
			t.Fatalf("Verify failed for self-produced proof: %v", err)
		}
		if !bytes.Equal(beta1, beta2) {
			t.Fatalf("beta mismatch: got %x vs %x", beta1, beta2)
		}

		// Negative check: mutate the proof slightly and expect verification to fail
		if len(pi) > 0 {
			mutated := make([]byte, len(pi))
			copy(mutated, pi)
			mutated[0] ^= 0x01
			if !bytes.Equal(mutated, pi) {
				if _, err := vrf.Verify(&sk.PublicKey, alpha, mutated); err == nil {
					t.Fatalf("mutated proof unexpectedly verified")
				}
			}
		}
	})
}

func FuzzProveVerifyP256(f *testing.F) {
	// Seed with a simple example
	f.Add([]byte("Hello VeChain"), []byte{2})
	f.Add([]byte{0x10, 0x20}, []byte{0x01, 0x02, 0x03})

	f.Fuzz(func(t *testing.T, alpha []byte, skSeed []byte) {
		sk := deriveP256Key(skSeed)
		if sk == nil {
			t.Skip()
		}

		vrf := P256Sha256Tai

		beta1, pi, err := vrf.Prove(sk, alpha)
		if err != nil {
			// Not all inputs must be valid; just ensure no panic and continue.
			return
		}

		beta2, err := vrf.Verify(&sk.PublicKey, alpha, pi)
		if err != nil {
			t.Fatalf("Verify failed for self-produced proof: %v", err)
		}
		if !bytes.Equal(beta1, beta2) {
			t.Fatalf("beta mismatch: got %x vs %x", beta1, beta2)
		}

		// Negative check: mutate the proof slightly and expect verification to fail
		if len(pi) > 0 {
			mutated := make([]byte, len(pi))
			copy(mutated, pi)
			mutated[0] ^= 0x01
			if !bytes.Equal(mutated, pi) {
				if _, err := vrf.Verify(&sk.PublicKey, alpha, mutated); err == nil {
					t.Fatalf("mutated proof unexpectedly verified")
				}
			}
		}
	})
}

// makeSecp256k1Key directly constructs a private key from raw bytes without derivation.
// It may return a private key with public key that is NOT on curve (for fuzzing purposes).
func makeSecp256k1Key(data []byte) *ecdsa.PrivateKey {
	if len(data) == 0 {
		return nil
	}
	curve := secp256k1.S256()
	q := curve.Params().N

	// If data is at least 96 bytes (32 for D + 32 for X + 32 for Y), try to construct
	// private key with potentially invalid public key coordinates
	if len(data) >= 96 {
		// First 32 bytes as private key scalar D
		privKeyBytes := make([]byte, 32)
		copy(privKeyBytes, data[:32])
		d := new(big.Int).SetBytes(privKeyBytes)
		if d.Sign() == 0 || d.Cmp(q) >= 0 {
			d.Mod(d, new(big.Int).Sub(q, big.NewInt(1)))
			d.Add(d, big.NewInt(1))
		}

		// Next 32 bytes as X coordinate (may not be on curve)
		x := new(big.Int).SetBytes(data[32:64])
		// Next 32 bytes as Y coordinate (may not be on curve)
		y := new(big.Int).SetBytes(data[64:96])

		// Don't check IsOnCurve - allow testing invalid points
		return &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
			D:         d,
		}
	}

	// Use data directly as private key scalar (standard case, always on curve)
	privKeyBytes := make([]byte, 32)
	if len(data) <= 32 {
		copy(privKeyBytes[32-len(data):], data)
	} else {
		copy(privKeyBytes, data[:32])
	}

	d := new(big.Int).SetBytes(privKeyBytes)
	if d.Sign() == 0 || d.Cmp(q) >= 0 {
		d.Mod(d, new(big.Int).Sub(q, big.NewInt(1)))
		d.Add(d, big.NewInt(1))
	}

	sk := secp256k1.PrivKeyFromBytes(d.Bytes())
	return sk.ToECDSA()
}

// makeP256Key directly constructs a private key from raw bytes without derivation.
// It may return a private key with public key that is NOT on curve (for fuzzing purposes).
func makeP256Key(data []byte) *ecdsa.PrivateKey {
	if len(data) == 0 {
		return nil
	}
	curve := elliptic.P256()
	q := curve.Params().N

	// If data is at least 96 bytes (32 for D + 32 for X + 32 for Y), try to construct
	// private key with potentially invalid public key coordinates
	if len(data) >= 96 {
		// First 32 bytes as private key scalar D
		d := new(big.Int).SetBytes(data[:32])
		if d.Sign() == 0 || d.Cmp(q) >= 0 {
			d.Mod(d, new(big.Int).Sub(q, big.NewInt(1)))
			d.Add(d, big.NewInt(1))
		}

		// Next 32 bytes as X coordinate (may not be on curve)
		x := new(big.Int).SetBytes(data[32:64])
		// Next 32 bytes as Y coordinate (may not be on curve)
		y := new(big.Int).SetBytes(data[64:96])

		// Don't check IsOnCurve - allow testing invalid points
		return &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
			D:         d,
		}
	}

	// Standard case: use data as private key scalar (always generates valid on-curve point)
	d := new(big.Int).SetBytes(data)
	if d.Sign() == 0 || d.Cmp(q) >= 0 {
		d.Mod(d, new(big.Int).Sub(q, big.NewInt(1)))
		d.Add(d, big.NewInt(1))
	}

	x, y := curve.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}
}

// makeSecp256k1PublicKey directly constructs a public key from raw bytes.
// It may return a public key that is NOT on curve (for fuzzing purposes).
func makeSecp256k1PublicKey(data []byte) *ecdsa.PublicKey {
	if len(data) == 0 {
		return nil
	}

	// Try to parse as public key (compressed or uncompressed)
	pubKey, err := secp256k1.ParsePubKey(data)
	if err == nil {
		return pubKey.ToECDSA()
	}

	// If data is at least 64 bytes, try to construct from X and Y directly
	// This allows fuzzer to generate random X, Y coordinates that may not be on curve
	if len(data) >= 64 {
		curve := secp256k1.S256()
		x := new(big.Int).SetBytes(data[:32])
		y := new(big.Int).SetBytes(data[32:64])
		// Don't check IsOnCurve - allow testing invalid points
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	}

	// If parsing fails, construct from private key (this will always be on curve)
	sk := makeSecp256k1Key(data)
	if sk != nil {
		return &sk.PublicKey
	}
	return nil
}

// makeP256PublicKey directly constructs a public key from raw bytes.
// It may return a public key that is NOT on curve (for fuzzing purposes).
func makeP256PublicKey(data []byte) *ecdsa.PublicKey {
	if len(data) == 0 {
		return nil
	}

	curve := elliptic.P256()

	// Try uncompressed format (0x04 || X || Y)
	if len(data) >= 65 && data[0] == 0x04 {
		x := new(big.Int).SetBytes(data[1:33])
		y := new(big.Int).SetBytes(data[33:65])
		// Don't check IsOnCurve here - allow fuzzer to test invalid points
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	}

	// Try compressed format
	if len(data) >= 33 && (data[0] == 0x02 || data[0] == 0x03) {
		x, y := elliptic.UnmarshalCompressed(curve, data)
		if x != nil && y != nil {
			return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		}
	}

	// If data is at least 64 bytes, try to construct from X and Y directly (without format byte)
	// This allows fuzzer to generate random X, Y coordinates that may not be on curve
	if len(data) >= 64 {
		x := new(big.Int).SetBytes(data[:32])
		y := new(big.Int).SetBytes(data[32:64])
		// Don't check IsOnCurve - allow testing invalid points
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	}

	// If parsing fails, construct from private key (this will always be on curve)
	sk := makeP256Key(data)
	if sk != nil {
		return &sk.PublicKey
	}

	return nil
}

// FuzzProveVerifyRandomKeysP256 fuzzes Prove and Verify with random private key and public key inputs for P256 curve.
func FuzzProveVerifyRandomKeysP256(f *testing.F) {
	f.Add([]byte{0x01, 0x02}, []byte{0x03, 0x04}, []byte("alpha"))

	sk := makeP256Key([]byte("test_seed_123456789012345678901234567890"))
	if sk != nil {
		pubKeyBytes := elliptic.MarshalCompressed(elliptic.P256(), sk.X, sk.Y)
		f.Add(sk.D.Bytes(), pubKeyBytes, []byte("test"))
	}

	f.Fuzz(func(t *testing.T, skBytes []byte, pkBytes []byte, alpha []byte) {
		sk := makeP256Key(skBytes)
		if sk == nil {
			t.Skip()
		}

		vrf := P256Sha256Tai

		beta1, pi, err := vrf.Prove(sk, alpha)
		if err != nil {
			return
		}

		beta2, err := vrf.Verify(&sk.PublicKey, alpha, pi)
		if err != nil {
			t.Fatalf("P256 Verify failed: %v", err)
		}
		if !bytes.Equal(beta1, beta2) {
			t.Fatalf("P256 beta mismatch: got %x vs %x", beta1, beta2)
		}
	})
}

// FuzzProveVerifyRandomKeysSecp256k1 fuzzes Prove and Verify with random private key and public key inputs for secp256k1 curve.
func FuzzProveVerifyRandomKeysSecp256k1(f *testing.F) {
	f.Add([]byte{0x01, 0x02}, []byte{0x03, 0x04}, []byte("alpha"))

	sk := makeSecp256k1Key([]byte("test_seed_123456789012345678901234567890"))
	if sk != nil {
		var x, y secp256k1.FieldVal
		x.SetByteSlice(sk.X.Bytes())
		y.SetByteSlice(sk.Y.Bytes())
		pubKey := secp256k1.NewPublicKey(&x, &y)
		pubKeyBytes := pubKey.SerializeCompressed()
		f.Add(sk.D.Bytes(), pubKeyBytes, []byte("test"))
	}

	f.Fuzz(func(t *testing.T, skBytes []byte, pkBytes []byte, alpha []byte) {
		sk := makeSecp256k1Key(skBytes)
		if sk == nil {
			t.Skip()
		}

		vrf := Secp256k1Sha256Tai

		beta1, pi, err := vrf.Prove(sk, alpha)
		if err != nil {
			return
		}

		beta2, err := vrf.Verify(&sk.PublicKey, alpha, pi)
		if err != nil {
			t.Fatalf("secp256k1 Verify failed: %v", err)
		}
		if !bytes.Equal(beta1, beta2) {
			t.Fatalf("secp256k1 beta mismatch: got %x vs %x", beta1, beta2)
		}
	})
}
