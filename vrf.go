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

func NewSecp256k1Sha256Tai() VRF {
	cfg := func(curve elliptic.Curve) *config {
		return &config{
			curve,
			0xfe,
			1,
			sha256.New,
			func(x *big.Int) *big.Int {
				// y² = x³ + b
				x3 := new(big.Int).Mul(x, x)
				x3.Mul(x3, x)

				x3.Add(x3, curve.Params().B)
				x3.Mod(x3, curve.Params().P)
				return x3
			},
			defaultSqrt,
		}
	}
	return &vrf{cfg}
}

type vrf struct {
	cfg func(curve elliptic.Curve) *config
}

func (v *vrf) Prove(sk *ecdsa.PrivateKey, m []byte) (hash []byte, proof []byte, err error) {
	var (
		cfg  = v.cfg(sk.Curve)
		q    = cfg.Q()
		qlen = q.BitLen()
	)

	// step 1: Hash to curve
	hx, hy, err := cfg.HashToCurveTryAndIncrement(sk.X, sk.Y, m)
	if err != nil {
		return
	}

	// step 2: point to string
	hbytes := cfg.Marshal(hx, hy)

	// step 3: gamma = x * H
	gammaX, gammaY := cfg.ScalarMult(hx, hy, sk.D.Bytes())

	// step 4: nonce
	k := cfg.GenerateNonce(sk.D, cfg.Hash(hbytes))
	kbytes := k.Bytes()

	// step 5: c = hash points
	ux, uy := cfg.ScalarBaseMult(kbytes)
	vx, vy := cfg.ScalarMult(hx, hy, kbytes)
	c := cfg.HashPoints([]struct{ x, y *big.Int }{
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
	gammaBytes := cfg.Marshal(gammaX, gammaY)

	cbytes := int2octets(c, (cfg.OneN()+7)/8)
	sbytes := int2octets(s, (qlen+7)/8)

	proof = append(append(gammaBytes, cbytes...), sbytes...)
	hash = cfg.GammaToHash(gammaX, gammaY)
	return
}

func (v *vrf) Verify(pk *ecdsa.PublicKey, m []byte, proof []byte) (hash []byte, err error) {
	// TODO
	return
}
