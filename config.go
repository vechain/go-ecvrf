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
	// a single nonzero octet specifying the ECVRF ciphersuite.
	SuiteString byte
	// number of points on curve divided by group order.
	Cofactor byte
	// create cryptographic hash function.
	NewHasher func() hash.Hash
	// function to calculate y^2.
	Y2 func(c elliptic.Curve, x *big.Int) *big.Int
	// function to calculate square root.
	Sqrt func(c elliptic.Curve, s *big.Int) *big.Int
}

// DefaultSqrt is the default sqrt method. nil is returned if s is not a square.
func DefaultSqrt(c elliptic.Curve, s *big.Int) *big.Int {
	var r big.Int
	if nil == r.ModSqrt(s, c.Params().P) {
		return nil // s is not a square
	}
	return &r
}
