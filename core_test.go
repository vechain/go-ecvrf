// Copyright (c) 2020 vechain.org.
// Licensed under the MIT license.

package ecvrf

import (
	"math/big"
	"testing"
)

// TestDecodeProofValidation tests the validation logic in DecodeProof function
func TestDecodeProofValidation(t *testing.T) {
	// Use secp256k1 curve for testing
	// Create a temporary vrf instance to get the config
	tempVrf := Secp256k1Sha256Tai.(*vrf)
	core := &core{Config: &tempVrf.cfg}

	// Generate a valid point for testing
	// Use the generator point of secp256k1 curve
	validPoint := &point{
		X: core.Curve.Params().Gx,
		Y: core.Curve.Params().Gy,
	}

	// Calculate valid proof length
	q := core.Q()
	ptlen := (core.Curve.Params().BitSize+7)/8 + 1
	clen := core.N()
	slen := (q.BitLen() + 7) / 8

	t.Run("test case when C value is zero", func(t *testing.T) {
		// Create a valid proof but with C value as zero
		pi := make([]byte, ptlen+clen+slen)

		// Set valid gamma point
		gammaBytes := core.Marshal(validPoint)
		copy(pi[:ptlen], gammaBytes)

		// Set C to zero
		// C bytes are already zero, no need for additional setup

		// Set valid S value
		sValue := big.NewInt(12345)
		sBytes := int2octets(sValue, slen)
		copy(pi[ptlen+clen:], sBytes)

		_, _, _, err := core.DecodeProof(pi)
		if err == nil {
			t.Error("expected error but got nil")
		}
		if err.Error() != "invalid proof: value c is zero" {
			t.Errorf("expected error message 'invalid proof: value c is zero', but got: %v", err)
		}
	})

	t.Run("test case when S value is zero", func(t *testing.T) {
		// Create a valid proof but with S value as zero
		pi := make([]byte, ptlen+clen+slen)

		// Set valid gamma point
		gammaBytes := core.Marshal(validPoint)
		copy(pi[:ptlen], gammaBytes)

		// Set valid C value
		cValue := big.NewInt(12345)
		cBytes := int2octets(cValue, clen)
		copy(pi[ptlen:ptlen+clen], cBytes)

		// Set S to zero
		// S bytes are already zero, no need for additional setup

		_, _, _, err := core.DecodeProof(pi)
		if err == nil {
			t.Error("expected error but got nil")
		}
		if err.Error() != "invalid proof: value s is zero" {
			t.Errorf("expected error message 'invalid proof: value s is zero', but got: %v", err)
		}
	})

	t.Run("test case when S value is out of range", func(t *testing.T) {
		// Create a valid proof but with S value >= curve order
		pi := make([]byte, ptlen+clen+slen)

		// Set valid gamma point
		gammaBytes := core.Marshal(validPoint)
		copy(pi[:ptlen], gammaBytes)

		// Set valid C value
		cValue := big.NewInt(12345)
		cBytes := int2octets(cValue, clen)
		copy(pi[ptlen:ptlen+clen], cBytes)

		// Set S to curve order (out of range)
		sValue := new(big.Int).Set(q)
		sBytes := int2octets(sValue, slen)
		copy(pi[ptlen+clen:], sBytes)

		_, _, _, err := core.DecodeProof(pi)
		if err == nil {
			t.Error("expected error but got nil")
		}
		if err.Error() != "invalid proof: s value out of range (>= curve order)" {
			t.Errorf("expected error message 'invalid proof: s value out of range (>= curve order)', but got: %v", err)
		}
	})

	t.Run("test case when S value equals curve order minus 1 (boundary value)", func(t *testing.T) {
		// Create a valid proof with S value = curve order - 1 (should pass validation)
		pi := make([]byte, ptlen+clen+slen)

		// Set valid gamma point
		gammaBytes := core.Marshal(validPoint)
		copy(pi[:ptlen], gammaBytes)

		// Set valid C value
		cValue := big.NewInt(12345)
		cBytes := int2octets(cValue, clen)
		copy(pi[ptlen:ptlen+clen], cBytes)

		// Set S to curve order minus 1 (valid range)
		sValue := new(big.Int).Sub(q, big.NewInt(1))
		sBytes := int2octets(sValue, slen)
		copy(pi[ptlen+clen:], sBytes)

		_, _, _, err := core.DecodeProof(pi)
		if err != nil {
			t.Errorf("expected no error, but got: %v", err)
		}
	})

	t.Run("test case when S value equals 1 (boundary value)", func(t *testing.T) {
		// Create a valid proof with S value = 1 (should pass validation)
		pi := make([]byte, ptlen+clen+slen)

		// Set valid gamma point
		gammaBytes := core.Marshal(validPoint)
		copy(pi[:ptlen], gammaBytes)

		// Set valid C value
		cValue := big.NewInt(12345)
		cBytes := int2octets(cValue, clen)
		copy(pi[ptlen:ptlen+clen], cBytes)

		// Set S to 1 (valid range)
		sValue := big.NewInt(1)
		sBytes := int2octets(sValue, slen)
		copy(pi[ptlen+clen:], sBytes)

		_, _, _, err := core.DecodeProof(pi)
		if err != nil {
			t.Errorf("expected no error, but got: %v", err)
		}
	})
}
