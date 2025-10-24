package ecvrf

import (
	"testing"
)

func FuzzDecodeProofSecp256k1(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0x02, 0x01})

	f.Fuzz(func(t *testing.T, pi []byte) {
		// Retrieve core config from the preconfigured VRF
		temp := Secp256k1Sha256Tai.(*vrf)
		c := &core{Config: &temp.cfg}

		// Ensure no panic occurs during decoding
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DecodeProof panicked: %v", r)
			}
		}()

		_, _, _, _ = c.DecodeProof(pi)
	})
}

func FuzzDecodeProofP256(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0x02, 0x01})

	f.Fuzz(func(t *testing.T, pi []byte) {
		temp := P256Sha256Tai.(*vrf)
		c := &core{Config: &temp.cfg}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DecodeProof panicked: %v", r)
			}
		}()

		_, _, _, _ = c.DecodeProof(pi)
	})
}

func FuzzHashToCurveTryAndIncrementSecp256k1(f *testing.F) {
	f.Add([]byte("Hello"), []byte{1})
	f.Add([]byte{0x01, 0x02, 0x03}, []byte{0xFF})

	f.Fuzz(func(t *testing.T, alpha []byte, skSeed []byte) {
		sk := deriveSecp256k1Key(skSeed)
		if sk == nil {
			t.Skip()
		}
		temp := Secp256k1Sha256Tai.(*vrf)
		c := &core{Config: &temp.cfg}
		H, err := c.HashToCurveTryAndIncrement(&point{sk.PublicKey.X, sk.PublicKey.Y}, alpha)
		if err != nil {
			// No guarantee that a valid point is found for all inputs; just ensure no panic.
			return
		}
		if c.Unmarshal(c.Marshal(H)) == nil {
			t.Fatalf("returned point is not on curve")
		}
	})
}

func FuzzHashToCurveTryAndIncrementP256(f *testing.F) {
	f.Add([]byte("Hello"), []byte{2})
	f.Add([]byte{0x01, 0x02, 0x03}, []byte{0x01, 0x02})

	f.Fuzz(func(t *testing.T, alpha []byte, skSeed []byte) {
		if len(skSeed) == 0 {
			t.Skip()
		}
		temp := P256Sha256Tai.(*vrf)
		c := &core{Config: &temp.cfg}

		sk := deriveP256Key(skSeed)
		if sk == nil {
			t.Skip()
		}

		H, err := c.HashToCurveTryAndIncrement(&point{sk.PublicKey.X, sk.PublicKey.Y}, alpha)
		if err != nil {
			return
		}
		if c.Unmarshal(c.Marshal(H)) == nil {
			t.Fatalf("returned point is not on curve")
		}
	})
}
