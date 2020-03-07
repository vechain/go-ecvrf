// Copyright (c) 2020 vechain.org.
// Licensed under the MIT license.

package ecvrf

import (
	"crypto/elliptic"
	"hash"
	"math/big"
)

type Config struct {
	SuiteString byte
	Cofactor    byte
	Hasher      func() hash.Hash
	Y2          func(c elliptic.Curve, x *big.Int) *big.Int
	Sqrt        func(c elliptic.Curve, s *big.Int) *big.Int
}
