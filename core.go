// Copyright (c) 2020 vechain.org.
// Licensed under the MIT license.

package ecvrf

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"errors"
	"hash"
	"math/big"
)

type point struct {
	X, Y *big.Int
}

type core struct {
	*Config
	curve        elliptic.Curve
	cachedHasher hash.Hash
}

// Q returns prime order of large prime order subgroup.
func (c *core) Q() *big.Int {
	return c.curve.Params().N
}

// N return half of length, in octets, of a field element in F, rounded up to the nearest even integer
func (c *core) N() int {
	return ((c.curve.Params().P.BitLen()+1)/2 + 7) / 8
}

func (c *core) getCachedHasher() hash.Hash {
	if c.cachedHasher != nil {
		return c.cachedHasher
	}
	c.cachedHasher = c.NewHasher()
	return c.cachedHasher
}

// Marshal marshals a point into compressed form specified in section 4.3.6 of ANSI X9.62.
// It's the alias of `point_to_string` specified in [draft-irtf-cfrg-vrf-06 section 5.5](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.5).
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

// Unmarshal unmarshals a compressed point in the form specified in section 4.3.6 of ANSI X9.62.
// It's the alias of `string_to_point` specified in [draft-irtf-cfrg-vrf-06 section 5.5](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.5).
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

func (c *core) ScalarMult(pt *point, k []byte) *point {
	x, y := c.curve.ScalarMult(pt.X, pt.Y, k)
	return &point{x, y}
}

func (c *core) ScalarBaseMult(k []byte) *point {
	x, y := c.curve.ScalarBaseMult(k)
	return &point{x, y}
}

func (c *core) Add(pt1, pt2 *point) *point {
	x, y := c.curve.Add(pt1.X, pt1.Y, pt2.X, pt2.Y)
	return &point{x, y}
}

func (c *core) Sub(pt1, pt2 *point) *point {
	// pt1 - pt2 = pt1 + invert(pt2),
	// where invert(pt2) = (x2, P - y2)
	x, y := c.curve.Add(
		pt1.X, pt1.Y,
		pt2.X, new(big.Int).Sub(c.curve.Params().P, pt2.Y))
	return &point{x, y}
}

// HashToCurveTryAndIncrement takes in the VRF input `alpha` and converts it to H, using the try_and_increment algorithm.
// See: [draft-irtf-cfrg-vrf-06 section 5.4.1.1](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.4.1.1).
func (c *core) HashToCurveTryAndIncrement(pk *point, alpha []byte) (H *point, err error) {
	hasher := c.getCachedHasher()
	hash := make([]byte, 1+hasher.Size())
	hash[0] = 2 // compress format

	// step 1: ctr = 0
	ctr := 0

	// step 2: PK_string = point_to_string(Y)
	pkBytes := c.Marshal(pk)

	// step 3 ~ 6
	prefix := []byte{c.SuiteString, 0x01}
	suffix := []byte{0}
	for ; ctr < 256; ctr++ {
		// hash_string = Hash(suite_string || one_string || PK_string || alpha_string || ctr_string)
		suffix[0] = byte(ctr)
		hasher.Reset()
		hasher.Write(prefix)
		hasher.Write(pkBytes)
		hasher.Write(alpha)
		hasher.Write(suffix)
		// apppend right after compress format
		hasher.Sum(hash[1:1])

		// H = arbitrary_string_to_point(hash_string)
		if H, err = c.Unmarshal(hash); err == nil {
			if c.Cofactor > 1 {
				// If H is not "INVALID" and cofactor > 1, set H = cofactor * H
				H = c.ScalarMult(H, []byte{c.Cofactor})
			}
			return H, nil
		}
	}
	return nil, errors.New("no valid point found")
}

// See: [draft-irtf-cfrg-vrf-06 section 5.4.3](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.4.3)
func (c *core) HashPoints(points ...*point) *big.Int {
	hasher := c.getCachedHasher()
	hasher.Reset()

	hasher.Write([]byte{c.SuiteString, 0x2})
	for _, pt := range points {
		hasher.Write(c.Marshal(pt))
	}
	return bits2int(hasher.Sum(nil), c.N()*8)
}

func (c *core) GammaToHash(gamma *point) []byte {
	gammaCof := gamma
	if c.Cofactor != 1 {
		gammaCof = c.ScalarMult(gamma, []byte{c.Cofactor})
	}
	hasher := c.getCachedHasher()
	hasher.Reset()
	hasher.Write([]byte{c.SuiteString, 0x03})
	hasher.Write(c.Marshal(gammaCof))
	return hasher.Sum(nil)
}

func (c *core) EncodeProof(gamma *point, C, S *big.Int) []byte {
	gammaBytes := c.Marshal(gamma)

	cbytes := int2octets(C, c.N())
	sbytes := int2octets(S, (c.Q().BitLen()+7)/8)

	return append(append(gammaBytes, cbytes...), sbytes...)
}

// See: [draft-irtf-cfrg-vrf-06 section 5.4.4](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.4.4)
func (c *core) DecodeProof(pi []byte) (gamma *point, C, S *big.Int, err error) {
	var (
		ptlen = (c.curve.Params().BitSize+7)/8 + 1
		clen  = c.N()
		slen  = (c.Q().BitLen() + 7) / 8
	)
	if len(pi) != ptlen+clen+slen {
		err = errors.New("invalid proof length")
		return
	}

	if gamma, err = c.Unmarshal(pi[:ptlen]); err != nil {
		return
	}

	C = new(big.Int).SetBytes(pi[ptlen : ptlen+clen])
	S = new(big.Int).SetBytes(pi[ptlen+clen:])
	return
}

// https://tools.ietf.org/html/rfc6979#section-2.3.2
func bits2int(in []byte, qlen int) *big.Int {
	out := new(big.Int).SetBytes(in)
	if inlen := len(in) * 8; inlen > qlen {
		return out.Rsh(out, uint(inlen-qlen))
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

// rfc6979nonce generates nonce according to [RFC6979](https://tools.ietf.org/html/rfc6979).
func rfc6979nonce(
	sk *big.Int,
	m []byte,
	q *big.Int,
	newHasher func() hash.Hash,
) *big.Int {
	var (
		qlen   = q.BitLen()
		rolen  = (qlen + 7) / 8
		hasher = newHasher()
	)

	// Step A
	// Process m through the hash function H, yielding:
	// h1 = H(m)
	// (h1 is a sequence of hlen bits).
	hasher.Write(m)
	h1 := hasher.Sum(nil)
	hlen := len(h1)

	bx := int2octets(sk, rolen)
	bh := bits2octets(h1, q, rolen)

	// Step B
	// Set:
	// V = 0x01 0x01 0x01 ... 0x01
	v := bytes.Repeat([]byte{1}, hlen)

	// Step C
	// Set:
	// K = 0x00 0x00 0x00 ... 0x00
	k := make([]byte, hlen)

	// Step D ~ G
	for i := 0; i < 2; i++ {
		// Set:
		// K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
		mac := hmac.New(newHasher, k)
		mac.Write(v)
		mac.Write([]byte{byte(i)}) // internal octet
		mac.Write(bx)
		mac.Write(bh)
		mac.Sum(k[:0])

		// Set:
		// V = HMAC_K(V)
		mac = hmac.New(newHasher, k)
		mac.Write(v)
		mac.Sum(v[:0])
	}

	// Step H
	for {
		// Step H1
		var t []byte

		// Step H2
		mac := hmac.New(newHasher, k)
		for len(t)*8 < qlen {
			mac.Write(v)
			mac.Sum(v[:0])
			mac.Reset()

			t = append(t, v...)
		}

		// Step H3
		secret := bits2int(t, qlen)
		if secret.Sign() > 0 && secret.Cmp(q) < 0 {
			return secret
		}
		mac.Write(v)
		mac.Write([]byte{0x00})
		mac.Sum(k[:0])

		mac = hmac.New(newHasher, k)
		mac.Write(v)
		mac.Sum(v[:0])
	}
}
