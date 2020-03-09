## *DO NOT USE: It's an incomplete work-in-progress!!!*

# go-ecvrf

Zero-dependency Golang implementation of Elliptic Curve Verifiable Random Function (VRF) follows [draft-irtf-cfrg-vrf-06](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html) and [RFC 6979](https://tools.ietf.org/html/rfc6979).

# What's VRF

TODO

# Installation

```
go get -u github.com/vechain/go-ecvrf
```

# Examples

TODO

# Supported Cipher Suites

* P256_SHA256_TAI 
* SECP256K1_SHA256_TAI

It's easy to extends this library to use different Weierstrass curves and Hash algorithms, by providing cooked `Config` like:

```golang
// the following codes build a new P256_SHA256_TAI VRF object.
vrf := ecvrf.New(&ecvrf.Config{
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
    Sqrt: ecvrf.DefaultSqrt,
})
```

# References

* [draft-irtf-cfrg-vrf-06](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html)
* [RFC 6979](https://tools.ietf.org/html/rfc6979)
* [witnet/vrf-rs](https://github.com/witnet/vrf-rs)
* [google/keytransparency](https://github.com/google/keytransparency)

# License

Copyright (c) 2020 vechain.org.
Licensed under the MIT license.


