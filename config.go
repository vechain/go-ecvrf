// Copyright (c) 2020 vechain.org.
// Licensed under the MIT license.

package ecvrf

import (
	"crypto/elliptic"
	"hash"
	"math/big"
)

// Config contains VRF parameters.
type Config struct {
	// the elliptic curve.
	Curve elliptic.Curve
	// a single nonzero octet specifying the ECVRF ciphersuite.
	SuiteString byte
	// number of points on curve divided by group order.
	Cofactor byte
	// create cryptographic hash function.
	NewHasher func() hash.Hash
	// decompress the compressed public key into x and y coordinate.
	Decompress func(c elliptic.Curve, pk []byte) (x, y *big.Int)
}
