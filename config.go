package ecvrf

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"errors"
	"hash"
	"math/big"
)

type config struct {
	elliptic.Curve
	SuiteString byte
	Cofactor    byte
	Hasher      func() hash.Hash
	Y2          func(x *big.Int) *big.Int
	Sqrt        func(x, p *big.Int) *big.Int
}

func (c *config) Q() *big.Int {
	return c.Params().N
}

func (c *config) OneN() int {
	plen := c.Params().P.BitLen()
	return (plen + 1) / 2
}

// Marshal marshals a point into compressed form specified in section 4.3.6 of ANSI X9.62.
// It's the alias of `point_to_string` specified in VRF-draft-06 (https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.5).
func (c *config) Marshal(x, y *big.Int) []byte {
	byteLen := (c.Params().BitSize + 7) / 8
	out := make([]byte, byteLen+1)

	// compress format, 3 for odd y
	out[0] = 2 + byte(y.Bit(0))

	bytes := x.Bytes()

	if n := len(bytes); byteLen > n {
		copy(out[1+byteLen-n:], bytes)
	} else {
		copy(out[1:], bytes)
	}
	return out
}

// Unmarshal unmarshals a compressed point in the form specified in section 4.3.6 of ANSI X9.62.
// It's the alias of `string_to_point` specified in VRF-draft-06 (https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.5).
// This is borrowed from the project https://github.com/google/keytransparency.
func (c *config) Unmarshal(in []byte) (x, y *big.Int, err error) {
	byteLen := (c.Params().BitSize + 7) / 8
	if (in[0] &^ 1) != 2 {
		return nil, nil, errors.New("unrecognized point encoding")
	}
	if len(in) != 1+byteLen {
		return nil, nil, errors.New("invalid point data length")
	}
	// Based on Routine 2.2.4 in NIST Mathematical routines paper
	p := c.Params().P
	tx := new(big.Int).SetBytes(in[1 : 1+byteLen])
	y2 := c.Y2(tx)

	ty := c.Sqrt(y2, p)
	if ty == nil {
		return nil, nil, errors.New("invalid point: y^2 is not a squire")
	}

	var y2c big.Int
	y2c.Mul(ty, ty).Mod(&y2c, p)
	if y2c.Cmp(y2) != 0 {
		return nil, nil, errors.New("invalid point: sqrt(y2)^2 != y2")
	}

	if ty.Bit(0) != uint(in[0]&1) {
		ty.Sub(p, ty)
	}

	// valid point: return it
	return tx, ty, nil
}

func (c *config) Hash(data ...[]byte) []byte {
	h := c.Hasher()
	for _, e := range data {
		h.Write(e)
	}
	return h.Sum(nil)
}

func (c *config) Mac(k []byte, m ...[]byte) []byte {
	h := hmac.New(c.Hasher, k)
	for _, e := range m {
		h.Write(e)
	}
	return h.Sum(nil)
}

// HashToCurveTryAndIncrement https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.4.1.1
func (c *config) HashToCurveTryAndIncrement(pkX, pkY *big.Int, alpha []byte) (hx, hy *big.Int, err error) {
	pkBytes := c.Marshal(pkX, pkY)

	for ctr := 0; ctr < 256; ctr++ {
		hash := c.Hash(
			[]byte{c.SuiteString, 0x01},
			pkBytes,
			alpha,
			[]byte{byte(ctr)},
		)

		if hx, hy, err = c.Unmarshal(append([]byte{2}, hash...)); err == nil {
			break
		}
	}

	if hx == nil {
		return nil, nil, errors.New("no valid point found")
	}
	hx, hy = c.ScalarMult(hx, hy, []byte{c.Cofactor})
	return
}

func (c *config) GenerateNonce(sk *big.Int, hash []byte) *big.Int {
	var (
		q     = c.Q()
		qlen  = q.BitLen()
		rolen = (qlen + 7) / 8
		holen = len(hash)
		bh    = bits2octets(hash, q, rolen)
		bx    = int2octets(sk, rolen)
	)

	// Step B
	v := bytes.Repeat([]byte{1}, holen)

	// Step C
	k := make([]byte, holen)

	// Step D ~ G
	for i := 0; i < 2; i++ {
		k = c.Mac(
			k,
			v,
			[]byte{byte(i)},
			bx,
			bh,
		)
		v = c.Mac(k, v)
	}

	// Step H
	for {
		// Step H1
		var t []byte

		// Step H2
		for len(t)*8 < qlen {
			v = c.Mac(k, v)
			t = append(t, v...)
		}

		// Step H3
		secret := bits2int(t, qlen)
		if secret.Sign() > 0 && secret.Cmp(q) < 0 {
			return secret
		}
		k = c.Mac(k, append(v, 0x00))
		v = c.Mac(k, v)
	}
}

// https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.4.3
func (c *config) HashPoints(points ...struct{ x, y *big.Int }) *big.Int {
	v := []byte{c.SuiteString, 0x2}
	for _, pt := range points {
		v = append(v, c.Marshal(pt.x, pt.y)...)
	}

	hash := c.Hash(v)
	return bits2int(hash, c.OneN())
}

func (c *config) GammaToHash(x, y *big.Int) []byte {
	cx, cy := c.ScalarMult(x, y, []byte{c.Cofactor})

	gamma := c.Marshal(cx, cy)
	return c.Hash(
		[]byte{c.SuiteString, 0x03},
		gamma,
	)
}

// https://tools.ietf.org/html/rfc6979#section-2.3.2
func bits2int(in []byte, qlen int) *big.Int {
	out := new(big.Int).SetBytes(in)
	if ilen := len(in) * 8; ilen > qlen {
		return out.Rsh(out, uint(ilen-qlen))
	}
	return out
}

// https://tools.ietf.org/html/rfc6979#section-2.3.3
func int2octets(v *big.Int, rolen int) []byte {
	var (
		out    = v.Bytes()
		outlen = len(out)
	)

	// left pad with zeros if it's too short
	if rolen > outlen {
		out2 := make([]byte, rolen)
		copy(out2[rolen-outlen:], out)
		return out2
	}

	// drop most significant bytes if it's too long
	return out[outlen-rolen:]
}

// https://tools.ietf.org/html/rfc6979#section-2.3.4
func bits2octets(in []byte, q *big.Int, rolen int) []byte {
	z1 := bits2int(in, q.BitLen())
	z2 := new(big.Int).Sub(z1, q)
	if z2.Sign() < 0 {
		return int2octets(z1, rolen)
	}
	return int2octets(z2, rolen)
}

func defaultSqrt(x, p *big.Int) *big.Int {
	var r big.Int
	if nil == r.ModSqrt(x, p) {
		return nil // x is not a square
	}
	return &r
}
