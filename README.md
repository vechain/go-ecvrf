# go-ecvrf

[![GoDoc Reference](https://godoc.org/github.com/vechain/go-ecvrf?status.svg)](https://pkg.go.dev/github.com/vechain/go-ecvrf)
[![Travis](https://travis-ci.org/vechain/go-ecvrf.svg?branch=master)](https://travis-ci.org/vechain/go-ecvrf)
[![License](https://img.shields.io/github/license/vechain/go-ecvrf)](https://github.com/vechain/go-ecvrf/blob/master/LICENSE)

Zero-dependency Golang implementation of Elliptic Curve Verifiable Random Function (VRF) follows [draft-irtf-cfrg-vrf-06](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html) and [RFC 6979](https://tools.ietf.org/html/rfc6979).

# What's VRF

A Verifiable Random Function (VRF) is the public-key version of a keyed cryptographic hash. Only the holder of the private key can compute the hash, but anyone with public key can verify the correctness of the hash.

A key application of the VRF is to provide privacy against offline enumeration (e.g. dictionary attacks) on data stored in a hash-based data structure. In this application, a Prover holds the VRF private key and uses the VRF hashing to construct a hash-based data structure on the input data. Due to the nature of the VRF, only the Prover can answer queries about whether or not some data is stored in the data structure. Anyone who knows the public VRF key can verify that the Prover has answered the queries correctly. However no offline inferences (i.e. inferences without querying the Prover) can be made about the data stored in the data strucuture.

# Installation

```
go get -u github.com/vechain/go-ecvrf
```

# Examples

Using SECP256K1_SHA256_TAI cipher suite:

* VRF Proving

    ```golang
    // the private key
    var sk *ecdsa.PrivateKey
    // code to load sk
    // ... 

    // the input to be hashed by the VRF
    alpha := "Hello VeChain"

    // `beta`: the VRF hash output
    // `pi`: the VRF proof
    beta, pi, err := ecvrf.NewSecp256k1Sha256Tai().Prove(sk, []byte(alpha))
    if err != nil {
        // something wrong.
        // most likely sk is not properly loaded.
        return
    }
    ```

* VRF Verifying

    ```golang 
    // the public key
    var pk *ecdsa.PublicKey
    // code to load pk
    // ...

    // the input to be hashed by the VRF
    alpha := "Hello VeChain"

    // `pi` is the VRF proof
    beta, err := ecvrf.NewSecp256k1Sha256Tai().Verify(pk, []byte(alpha), pi)
    if err != nil {
        // invalid proof
        return
    }

    // got correct beta
    ```


# Supported Cipher Suites

* P256_SHA256_TAI 
* SECP256K1_SHA256_TAI

It's easy to extends this library to use different Weierstrass curves and Hash algorithms, by providing cooked `Config` like:

```golang
// the following codes build a new P256_SHA256_TAI VRF object.
vrf := ecvrf.New(&ecvrf.Config{
    SuiteString: 0x01,
    Cofactor:    0x01,
    NewHasher:   sha256.New,
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


