// Copyright (c) 2020 vechain.org.
// Licensed under the MIT license.

// Package ecvrf is the Elliptic Curve Verifiable Random Function (VRF) library.
package ecvrf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"
)

// VRF is the interface that wraps VRF methods.
type VRF interface {
	// Prove constructs a VRF proof `pi` for the given input `alpha`,
	// using the private key `sk`. The hash output is returned as `beta`.
	Prove(sk *ecdsa.PrivateKey, alpha []byte) (beta, pi []byte, err error)

	// Verify checks the proof `pi` of the message `alpha` against the given
	// public key `pk`. The hash output is returned as `beta`.
	Verify(pk *ecdsa.PublicKey, alpha, pi []byte) (beta []byte, err error)
}

// New creates and initializes a VRF object using customized config.
func New(cfg *Config) VRF {
	return &vrf{func(c elliptic.Curve) *core {
		return &core{cfg, c}
	}}
}

// NewSecp256k1Sha256Tai creates the VRF object configured with secp256k1/SHA256 and hash_to_curve_try_and_increment algorithm.
func NewSecp256k1Sha256Tai() VRF {
	return New(&Config{
		SuiteString: 0xfe,
		Cofactor:    0x01,
		Hasher:      sha256.New,
		Y2: func(c elliptic.Curve, x *big.Int) *big.Int {
			// y² = x³ + b
			x3 := new(big.Int).Mul(x, x)
			x3.Mul(x3, x)

			x3.Add(x3, c.Params().B)
			x3.Mod(x3, c.Params().P)
			return x3
		},
		Sqrt: DefaultSqrt,
	})
}

// NewP256Sha256Tai creates the VRF object configured with P256/SHA256 and hash_to_curve_try_and_increment algorithm.
func NewP256Sha256Tai() VRF {
	return New(&Config{
		SuiteString: 0x01,
		Cofactor:    0x01,
		Hasher:      sha256.New,
		Y2: func(c elliptic.Curve, x *big.Int) *big.Int {
			// y² = x³ - 3x + b
			x3 := new(big.Int).Mul(x, x)
			x3.Mul(x3, x)

			threeX := new(big.Int).Lsh(x, 1)
			threeX.Add(threeX, x)

			x3.Sub(x3, threeX)
			x3.Add(x3, c.Params().B)
			x3.Mod(x3, c.Params().P)
			return x3
		},
		Sqrt: DefaultSqrt,
	})
}

type vrf struct {
	newCore func(c elliptic.Curve) *core
}

// Prove constructs VRF proof following [draft-irtf-cfrg-vrf-06 section 5.1](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.1).
func (v *vrf) Prove(sk *ecdsa.PrivateKey, alpha []byte) (beta, pi []byte, err error) {
	var (
		core = v.newCore(sk.Curve)
		q    = core.Q()
	)
	// step 1 is done by the caller.

	// step 2: H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
	// currently, try_and_increment algorithm is supported
	H, err := core.HashToCurveTryAndIncrement(&point{sk.X, sk.Y}, alpha)
	if err != nil {
		return
	}

	// step 3: h_string = point_to_string(H)
	hbytes := core.Marshal(H)

	// step 4: Gamma = x * H
	gamma := core.ScalarMult(H, sk.D.Bytes())

	// step 5: k = ECVRF_nonce_generation(SK, h_string)
	// it follows RFC6979
	k := core.GenerateNonce(sk.D, hbytes)
	kbytes := k.Bytes()

	// step 6: c = ECVRF_hash_points(H, Gamma, k*B, k*H)
	kB := core.ScalarBaseMult(kbytes)
	kH := core.ScalarMult(H, kbytes)
	c := core.HashPoints(
		H,
		gamma,
		kB,
		kH)

	// step 7: s = (k + c*x) mod q
	s := new(big.Int).Mul(c, sk.D)
	s.Add(s, k)
	s.Mod(s, q)

	// step 8: encode (gamma, c, s) as pi_string = point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
	pi = core.EncodeProof(gamma, c, s)

	// step 9: Output pi_string
	// here also returns beta
	beta = core.GammaToHash(gamma)
	return
}

// Verify checks the correctness of proof following [draft-irtf-cfrg-vrf-06 section 5.3](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.3).
func (v *vrf) Verify(pk *ecdsa.PublicKey, alpha, pi []byte) (beta []byte, err error) {
	core := v.newCore(pk.Curve)

	// step 1: D = ECVRF_decode_proof(pi_string)
	gamma, c, s, err := core.DecodeProof(pi)

	// step 2: If D is "INVALID", output "INVALID" and stop
	if err != nil {
		return
	}
	// step 3: (Gamma, c, s) = D

	// step 4: H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
	H, err := core.HashToCurveTryAndIncrement(&point{pk.X, pk.Y}, alpha)
	if err != nil {
		return
	}

	// step 5: U = s*B - c*Y
	sB := core.ScalarBaseMult(s.Bytes())
	cY := core.ScalarMult(&point{pk.X, pk.Y}, c.Bytes())
	U := core.Sub(sB, cY)

	// step 6: V = s*H - c*Gamma
	sH := core.ScalarMult(H, s.Bytes())
	cGamma := core.ScalarMult(gamma, c.Bytes())
	V := core.Sub(sH, cGamma)

	// step 7: c' = ECVRF_hash_points(H, Gamma, U, V)
	derivedC := core.HashPoints(H, gamma, U, V)

	// step 8: If c and c' are equal, output ("VALID", ECVRF_proof_to_hash(pi_string)); else output "INVALID"
	if derivedC.Cmp(c) != 0 {
		err = errors.New("invalid proof")
		return
	}

	beta = core.GammaToHash(gamma)
	return
}
