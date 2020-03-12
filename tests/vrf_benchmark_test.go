// Copyright (c) 2020 vechain.org.
// Licensed under the MIT license.

package tests

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/vechain/go-ecvrf"
)

func BenchmarkSecp256k1Proving(b *testing.B) {
	sk, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	alpha := []byte("Hello VeChain")

	for i := 0; i < b.N; i++ {
		_, _, err := ecvrf.NewSecp256k1Sha256Tai().Prove(sk, alpha)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSecp256k1Verifying(b *testing.B) {
	sk, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	alpha := []byte("Hello VeChain")

	_, pi, _ := ecvrf.NewSecp256k1Sha256Tai().Prove(sk, alpha)
	for i := 0; i < b.N; i++ {
		_, err := ecvrf.NewSecp256k1Sha256Tai().Verify(&sk.PublicKey, alpha, pi)
		if err != nil {
			b.Fatal(err)
		}
	}
}
