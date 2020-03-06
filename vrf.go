package ecvrf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"
)

type VRF interface {
	Prove(sk *ecdsa.PrivateKey, m []byte) (beta, pi []byte, err error)
	Verify(pk *ecdsa.PublicKey, m, pi []byte) (beta []byte, err error)
}

func New(cfg *Config) VRF {
	return &vrf{func(c elliptic.Curve) *core {
		return &core{cfg, c}
	}}
}

func NewSecp256k1Sha256Tai() VRF {
	return New(&Config{
		0xfe,
		0x01,
		sha256.New,
		func(c elliptic.Curve, x *big.Int) *big.Int {
			// y² = x³ + b
			x3 := new(big.Int).Mul(x, x)
			x3.Mul(x3, x)

			x3.Add(x3, c.Params().B)
			x3.Mod(x3, c.Params().P)
			return x3
		},
		DefaultSqrt,
	})
}

func NewP256Sha256Tai() VRF {
	return New(&Config{
		0x01,
		0x01,
		sha256.New,
		func(c elliptic.Curve, x *big.Int) *big.Int {
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
		DefaultSqrt,
	})
}

type vrf struct {
	newCore func(c elliptic.Curve) *core
}

func (v *vrf) Prove(sk *ecdsa.PrivateKey, m []byte) (beta, pi []byte, err error) {
	var (
		core = v.newCore(sk.Curve)
		q    = core.Q()
	)

	// step 1: Hash to curve
	H, err := core.HashToCurveTryAndIncrement(&point{sk.X, sk.Y}, m)
	if err != nil {
		return
	}

	// step 2: point to string
	hbytes := core.Marshal(H)

	// step 3: gamma = x * H
	gamma := core.ScalarMult(H, sk.D.Bytes())

	// step 4: nonce
	k := core.GenerateNonce(sk.D, hbytes)
	kbytes := k.Bytes()

	// step 5: c = hash points
	upt := core.ScalarBaseMult(kbytes)
	vpt := core.ScalarMult(H, kbytes)
	c := core.HashPoints([]*point{
		H,
		gamma,
		upt,
		vpt,
	})

	// step 6: s = (k + c*x) mod q

	s := new(big.Int).Mul(c, sk.D)
	s.Add(s, k)
	s.Mod(s, q)

	// step 7: encode (gamma, c, s)
	pi = core.EncodeProof(&proof{gamma, c, s})

	beta = core.GammaToHash(gamma)
	return
}

func (v *vrf) Verify(pk *ecdsa.PublicKey, m, pi []byte) (beta []byte, err error) {
	core := v.newCore(pk.Curve)

	// step 1: decode proof
	proof, err := core.DecodeProof(pi)
	if err != nil {
		return
	}

	// step 2: hash to curve
	H, err := core.HashToCurveTryAndIncrement(&point{pk.X, pk.Y}, m)
	if err != nil {
		return
	}

	// step 3: U = sB - cY
	sB := core.ScalarBaseMult(proof.S.Bytes())
	cY := core.ScalarMult(&point{pk.X, pk.Y}, proof.C.Bytes())
	U := core.Sub(sB, cY)

	// step 4: V = sH - cGamma
	sH := core.ScalarMult(H, proof.S.Bytes())
	cGamma := core.ScalarMult(proof.Gamma, proof.C.Bytes())
	V := core.Sub(sH, cGamma)

	// step 5: hash points
	derivedC := core.HashPoints([]*point{
		H, proof.Gamma, U, V,
	})

	// step 6: check validity
	if derivedC.Cmp(proof.C) != 0 {
		err = errors.New("invalid proof")
		return
	}

	beta = core.GammaToHash(proof.Gamma)
	return
}
