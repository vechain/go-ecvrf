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
