package ecvrf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
)

type VRF interface {
	Prove(sk *ecdsa.PrivateKey, m []byte) (hash []byte, proof []byte, err error)
	Verify(pk *ecdsa.PublicKey, m []byte, proof []byte) (hash []byte, err error)
}

func New(cfg *Config) VRF {
	return &vrf{func(c elliptic.Curve) *core {
		return &core{cfg, c}
	}}
}

func NewSecp256k1Sha256Tai() VRF {
	return New(&Config{
		0xfe,
		1,
		sha256.New,
		func(c elliptic.Curve, x *big.Int) *big.Int {
			// y² = x³ + b
			x3 := new(big.Int).Mul(x, x)
			x3.Mul(x3, x)

			x3.Add(x3, c.Params().B)
			x3.Mod(x3, c.Params().P)
			return x3
		},
		defaultSqrt,
	})
}

type vrf struct {
	newCore func(c elliptic.Curve) *core
}

func (v *vrf) Prove(sk *ecdsa.PrivateKey, m []byte) (hash []byte, proof []byte, err error) {
	var (
		core = v.newCore(sk.Curve)
		q    = core.Q()
		qlen = q.BitLen()
	)

	// step 1: Hash to curve
	hx, hy, err := core.HashToCurveTryAndIncrement(sk.X, sk.Y, m)
	if err != nil {
		return
	}

	// step 2: point to string
	hbytes := core.Marshal(hx, hy)

	// step 3: gamma = x * H
	gammaX, gammaY := core.ScalarMult(hx, hy, sk.D.Bytes())

	// step 4: nonce
	k := core.GenerateNonce(sk.D, core.Hash(hbytes))
	kbytes := k.Bytes()

	// step 5: c = hash points
	ux, uy := core.ScalarBaseMult(kbytes)
	vx, vy := core.ScalarMult(hx, hy, kbytes)
	c := core.HashPoints([]struct{ x, y *big.Int }{
		{hx, hy},
		{gammaX, gammaY},
		{ux, uy},
		{vx, vy},
	}...)

	// step 6: s = (k + c*x) mod q

	s := new(big.Int).Mul(c, sk.D)
	s.Add(s, k)
	s.Mod(s, q)

	// step 7: encode (gamma, c, s)
	gammaBytes := core.Marshal(gammaX, gammaY)

	cbytes := int2octets(c, (core.OneN()+7)/8)
	sbytes := int2octets(s, (qlen+7)/8)

	proof = append(append(gammaBytes, cbytes...), sbytes...)
	hash = core.GammaToHash(gammaX, gammaY)
	return
}

func (v *vrf) Verify(pk *ecdsa.PublicKey, m []byte, proof []byte) (hash []byte, err error) {
	// TODO
	return
}
