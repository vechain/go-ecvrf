package tests

import (
	"encoding/hex"
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
		hex.EncodeToString(proof),
	)
	assert.Equal(t,
		"612065e309e937ef46c2ef04d5886b9c6efd2991ac484ec64a9b014366fc5d81",
		hex.EncodeToString(hash),
	)
}
