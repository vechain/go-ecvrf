package ecvrf

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"errors"
	"math/big"
)

type point struct {
	X, Y *big.Int
}

type proof struct {
	Gamma *point
	C, S  *big.Int
}

type core struct {
	*Config
	curve elliptic.Curve
}

func (c *core) Q() *big.Int {
	return c.curve.Params().N
}

func (c *core) OneN() int {
	plen := c.curve.Params().P.BitLen()
	return (plen + 1) / 2
}

// Marshal marshals a point into compressed form specified in section 4.3.6 of ANSI X9.62.
// It's the alias of `point_to_string` specified in VRF-draft-06 (https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.5).
func (c *core) Marshal(pt *point) []byte {
	byteLen := (c.curve.Params().BitSize + 7) / 8
	out := make([]byte, byteLen+1)

	// compress format, 3 for odd y
	out[0] = 2 + byte(pt.Y.Bit(0))

	bytes := pt.X.Bytes()

	if n := len(bytes); byteLen > n {
		copy(out[1+byteLen-n:], bytes)
	} else {
		copy(out[1:], bytes)
	}
	return out
}

func (c *core) ScalarMult(pt *point, k []byte) *point {
	var out point
	out.X, out.Y = c.curve.ScalarMult(pt.X, pt.Y, k)
	return &out
}

func (c *core) ScalarBaseMult(k []byte) *point {
	var out point
	out.X, out.Y = c.curve.ScalarBaseMult(k)
	return &out
}

func (c *core) Add(pt1, pt2 *point) *point {
	var out point
	out.X, out.Y = c.curve.Add(pt1.X, pt1.Y, pt2.X, pt2.Y)
	return &out
}

func (c *core) Sub(pt1, pt2 *point) *point {
	var out point
	// - (x, y) = (x, P - y)
	out.X, out.Y = c.curve.Add(
		pt1.X, pt1.Y,
		pt2.X, new(big.Int).Sub(c.curve.Params().P, pt2.Y))
	return &out
}

// Unmarshal unmarshals a compressed point in the form specified in section 4.3.6 of ANSI X9.62.
// It's the alias of `string_to_point` specified in VRF-draft-06 (https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.5).
// This is borrowed from the project https://github.com/google/keytransparency.
func (c *core) Unmarshal(in []byte) (*point, error) {
	byteLen := (c.curve.Params().BitSize + 7) / 8
	if (in[0] &^ 1) != 2 {
		return nil, errors.New("unrecognized point encoding")
	}
	if len(in) != 1+byteLen {
		return nil, errors.New("invalid point data length")
	}
	// Based on Routine 2.2.4 in NIST Mathematical routines paper
	p := c.curve.Params().P
	x := new(big.Int).SetBytes(in[1 : 1+byteLen])
	y2 := c.Y2(c.curve, x)

	y := c.Sqrt(c.curve, y2)
	if y == nil {
		return nil, errors.New("invalid point: y^2 is not a squire")
	}

	var y2c big.Int
	y2c.Mul(y, y).Mod(&y2c, p)
	if y2c.Cmp(y2) != 0 {
		return nil, errors.New("invalid point: sqrt(y2)^2 != y2")
	}

	if y.Bit(0) != uint(in[0]&1) {
		y.Sub(p, y)
	}

	// valid point: return it
	return &point{x, y}, nil
}

func (c *core) Hash(data ...[]byte) []byte {
	h := c.Hasher()
	for _, e := range data {
		h.Write(e)
	}
	return h.Sum(nil)
}

func (c *core) Mac(k []byte, m ...[]byte) []byte {
	h := hmac.New(c.Hasher, k)
	for _, e := range m {
		h.Write(e)
	}
	return h.Sum(nil)
}

// HashToCurveTryAndIncrement https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.4.1.1
func (c *core) HashToCurveTryAndIncrement(pk *point, alpha []byte) (*point, error) {
	var (
		pkBytes = c.Marshal(pk)
		pt      *point
		err     error
	)
	for ctr := 0; ctr < 256; ctr++ {
		hash := c.Hash(
			[]byte{c.SuiteString, 0x01},
			pkBytes,
			alpha,
			[]byte{byte(ctr)},
		)

		if pt, err = c.Unmarshal(append([]byte{2}, hash...)); err == nil {
			break
		}
	}
	if pt == nil {
		return nil, errors.New("no valid point found")
	}
	return c.ScalarMult(pt, []byte{c.Cofactor}), nil
}

func (c *core) GenerateNonce(sk *big.Int, hash []byte) *big.Int {
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
func (c *core) HashPoints(points []*point) *big.Int {
	v := []byte{c.SuiteString, 0x2}
	for _, pt := range points {
		v = append(v, c.Marshal(pt)...)
	}

	hash := c.Hash(v)
	return bits2int(hash, c.OneN())
}

func (c *core) GammaToHash(gamma *point) []byte {
	gammaCof := c.ScalarMult(gamma, []byte{c.Cofactor})
	return c.Hash(
		[]byte{c.SuiteString, 0x03},
		c.Marshal(gammaCof),
	)
}

func (c *core) EncodeProof(p *proof) []byte {
	gammaBytes := c.Marshal(p.Gamma)

	cbytes := int2octets(p.C, (c.OneN()+7)/8)
	sbytes := int2octets(p.S, (c.Q().BitLen()+7)/8)

	return append(append(gammaBytes, cbytes...), sbytes...)
}

func (c *core) DecodeProof(data []byte) (*proof, error) {
	var (
		qlen           = c.Q().BitLen()
		n              = c.OneN()
		gammaLen, clen int
	)
	if qlen%8 > 0 {
		gammaLen = qlen/8 + 2
	} else {
		gammaLen = qlen/8 + 1
	}
	if n%8 > 0 {
		clen = n/8 + 1
	} else {
		clen = n / 8
	}

	if len(data)*8 < gammaLen+clen*3 {
		return nil, errors.New("invalid proof length")
	}

	gamma, err := c.Unmarshal(data[0:gammaLen])
	if err != nil {
		return nil, err
	}
	var ret proof
	ret.Gamma = gamma
	ret.C = new(big.Int).SetBytes(data[gammaLen : gammaLen+clen])
	ret.S = new(big.Int).SetBytes(data[gammaLen+clen:])
	return &ret, nil
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

func DefaultSqrt(c elliptic.Curve, s *big.Int) *big.Int {
	var r big.Int
	if nil == r.ModSqrt(s, c.Params().P) {
		return nil // x is not a square
	}
	return &r
}
