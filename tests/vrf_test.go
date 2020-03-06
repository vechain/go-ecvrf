package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
	"github.com/vechain/go-ecvrf"
)

func TestSecp256k1Sha256Tai(t *testing.T) {
	vrf := ecvrf.NewSecp256k1Sha256Tai()

	skBytes, _ := hex.DecodeString("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
	sk, _ := btcec.PrivKeyFromBytes(btcec.S256(), skBytes)

	m, _ := hex.DecodeString("73616d706c65")

	hash, proof, err := vrf.Prove(sk.ToECDSA(), m)
	assert.Nil(t, err)
	assert.Equal(t,
		"031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d08748c9fbe6b95d17359707bfb8e8ab0c93ba0c515333adcb8b64f372c535e115ccf66ebf5abe6fadb01b5efb37c0a0ec9",
		hex.EncodeToString(proof))
	assert.Equal(t,
		"612065e309e937ef46c2ef04d5886b9c6efd2991ac484ec64a9b014366fc5d81",
		hex.EncodeToString(hash))

	vhash, err := vrf.Verify(sk.PubKey().ToECDSA(), m, proof)
	assert.Nil(t, err)
	assert.Equal(t,
		"612065e309e937ef46c2ef04d5886b9c6efd2991ac484ec64a9b014366fc5d81",
		hex.EncodeToString(vhash))
}

func TestP256Sha256Tai(t *testing.T) {
	vrf := ecvrf.NewP256Sha256Tai()

	skBytes, _ := hex.DecodeString("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
	curve := elliptic.P256()

	pkX, pkY := curve.ScalarBaseMult(skBytes)
	sk := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     pkX,
			Y:     pkY,
		},
		D: new(big.Int).SetBytes(skBytes),
	}

	m, _ := hex.DecodeString("73616d706c65")

	hash, proof, err := vrf.Prove(sk, m)
	assert.Nil(t, err)
	assert.Equal(t,
		"029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c524347fc46ccd87843ec0a9fdc090a407c6fbae8ac1480e240c58854897eabbc3a7bb61b201059f89186e7175af796d65e7",
		hex.EncodeToString(proof))

	assert.Equal(t,
		"59ca3801ad3e981a88e36880a3aee1df38a0472d5be52d6e39663ea0314e594c",
		hex.EncodeToString(hash))

}
