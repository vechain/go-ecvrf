// Copyright (c) 2022 vechain.org.
// Licensed under the MIT license.

package ecvrf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Case Testing cases structure.
type Case struct {
	Sk    string `json:"sk"`
	Pk    string `json:"pk"`
	Alpha string `json:"alpha"`
	Pi    string `json:"pi"`
	Beta  string `json:"beta"`
}

func readCases(fileName string) ([]Case, error) {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()

	byteValue, err2 := ioutil.ReadAll(jsonFile)
	if err2 != nil {
		return nil, err2
	}

	var cases = make([]Case, 0)
	err3 := json.Unmarshal(byteValue, &cases)
	if err3 != nil {
		return cases, err3
	}

	return cases, nil
}

func Test_Secp256K1Sha256Tai_vrf_Prove(t *testing.T) {
	// Know Correct cases.
	var cases, _ = readCases("./secp256_k1_sha256_tai.json")

	type Test struct {
		name     string
		sk       *ecdsa.PrivateKey
		alpha    []byte
		wantBeta []byte
		wantPi   []byte
		wantErr  bool
	}

	tests := []Test{}
	for _, c := range cases {
		skBytes, _ := hex.DecodeString(c.Sk)
		sk := secp256k1.PrivKeyFromBytes(skBytes)

		alpha, _ := hex.DecodeString(c.Alpha)
		wantBeta, _ := hex.DecodeString(c.Beta)
		wantPi, _ := hex.DecodeString(c.Pi)

		tests = append(tests, Test{
			c.Sk,
			sk.ToECDSA(),
			alpha,
			wantBeta,
			wantPi,
			false,
		})
	}

	vrf := Secp256k1Sha256Tai

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := vrf
			gotBeta, gotPi, err := v.Prove(tt.sk, tt.alpha)
			if (err != nil) != tt.wantErr {
				t.Errorf("vrf.Prove() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotBeta, tt.wantBeta) {
				t.Errorf("vrf.Prove() gotBeta = %v, want %v", hex.EncodeToString(gotBeta), hex.EncodeToString(tt.wantBeta))
			}
			if !reflect.DeepEqual(gotPi, tt.wantPi) {
				t.Errorf("vrf.Prove() gotPi = %v, want %v", hex.EncodeToString(gotPi), hex.EncodeToString(tt.wantPi))
			}
		})
	}
}

func Test_Secp256K1Sha256Tai_vrf_Verify(t *testing.T) {
	// Know Correct cases.
	var cases, _ = readCases("./secp256_k1_sha256_tai.json")

	type Test struct {
		name     string
		pk       *ecdsa.PublicKey
		alpha    []byte
		pi       []byte
		wantBeta []byte
		wantErr  bool
	}

	tests := []Test{}
	for _, c := range cases {
		skBytes, _ := hex.DecodeString(c.Sk)
		sk := secp256k1.PrivKeyFromBytes(skBytes)

		pk := sk.PubKey().ToECDSA()

		alpha, _ := hex.DecodeString(c.Alpha)

		wantPi, _ := hex.DecodeString(c.Pi)

		wantBeta, _ := hex.DecodeString(c.Beta)

		tests = append(tests, Test{
			c.Alpha,
			pk,
			alpha,
			wantPi,
			wantBeta,
			false,
		})
	}

	vrf := Secp256k1Sha256Tai

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := vrf
			gotBeta, err := v.Verify(tt.pk, tt.alpha, tt.pi)
			if (err != nil) != tt.wantErr {
				t.Errorf("vrf.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotBeta, tt.wantBeta) {
				t.Errorf("vrf.Verify() = %v, want %v", gotBeta, tt.wantBeta)
			}
		})
	}
}

func Test_Secp256K1Sha256Tai_vrf_Verify_bad_message(t *testing.T) {
	type Test struct {
		name     string
		pk       *ecdsa.PublicKey
		alpha    []byte
		pi       []byte
		wantBeta []byte
		wantErr  bool
	}

	// sk
	skBytes, _ := hex.DecodeString("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
	sk := secp256k1.PrivKeyFromBytes(skBytes)

	// pk
	pk := sk.PubKey().ToECDSA()

	// correct alpha
	// alpha, _ := hex.DecodeString("73616d706c65")
	wrongAlpha := []byte("Hello VeChain")
	// pi
	wantPi, _ := hex.DecodeString("031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d08748c9fbe6b95d17359707bfb8e8ab0c93ba0c515333adcb8b64f372c535e115ccf66ebf5abe6fadb01b5efb37c0a0ec9")

	// beta
	wantBeta, _ := hex.DecodeString("612065e309e937ef46c2ef04d5886b9c6efd2991ac484ec64a9b014366fc5d81")

	// test case
	tt := Test{
		"bad_message",
		pk,
		wrongAlpha,
		wantPi,
		wantBeta,
		true,
	}

	vrf := Secp256k1Sha256Tai

	t.Run(tt.name, func(t *testing.T) {
		v := vrf
		_, err := v.Verify(tt.pk, tt.alpha, tt.pi)
		if (err != nil) != tt.wantErr {
			t.Errorf("vrf.Verify() error = %v, wantErr %v", err, tt.wantErr)
			return
		}
	})

}

func Test_P256Sha256Tai_vrf_Prove(t *testing.T) {
	// Know Correct cases.
	var P256Sha256TaiCases, _ = readCases("./p256_sha256_tai.json")

	type Test struct {
		name     string
		sk       *ecdsa.PrivateKey
		alpha    []byte
		wantBeta []byte
		wantPi   []byte
		wantErr  bool
	}

	tests := []Test{}
	for _, c := range P256Sha256TaiCases {
		skBytes, _ := hex.DecodeString(c.Sk)
		curve := elliptic.P256()
		pkX, pkY := curve.ScalarBaseMult(skBytes)
		sk := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     pkX,
				Y:     pkY,
			},
			D: new(big.Int).SetBytes(skBytes),
		}
		alpha, _ := hex.DecodeString(c.Alpha)
		wantBeta, _ := hex.DecodeString(c.Beta)
		wantPi, _ := hex.DecodeString(c.Pi)

		tests = append(tests, Test{
			c.Alpha,
			sk,
			alpha,
			wantBeta,
			wantPi,
			false,
		})
	}

	vrf := P256Sha256Tai

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := vrf
			gotBeta, gotPi, err := v.Prove(tt.sk, tt.alpha)
			if (err != nil) != tt.wantErr {
				t.Errorf("vrf.Prove() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotBeta, tt.wantBeta) {
				t.Errorf("vrf.Prove() gotBeta = %v, want %v", gotBeta, tt.wantBeta)
			}
			if !reflect.DeepEqual(gotPi, tt.wantPi) {
				t.Errorf("vrf.Prove() gotPi = %v, want %v", gotPi, tt.wantPi)
			}
		})
	}
}

func Test_P256Sha256Tai_vrf_Verify(t *testing.T) {
	// Know Correct cases.
	var P256Sha256TaiCases, _ = readCases("./p256_sha256_tai.json")

	type Test struct {
		name     string
		pk       *ecdsa.PublicKey
		alpha    []byte
		pi       []byte
		wantBeta []byte
		wantErr  bool
	}

	tests := []Test{}
	for _, c := range P256Sha256TaiCases {
		curve := elliptic.P256()
		skBytes, _ := hex.DecodeString(c.Sk)

		pkX, pkY := curve.ScalarBaseMult(skBytes)
		pk := ecdsa.PublicKey{
			Curve: curve,
			X:     pkX,
			Y:     pkY,
		}

		alpha, _ := hex.DecodeString(c.Alpha)
		pi, _ := hex.DecodeString(c.Pi)
		wantBeta, _ := hex.DecodeString(c.Beta)

		tests = append(tests, Test{
			c.Alpha,
			&pk,
			alpha,
			pi,
			wantBeta,
			false,
		})
	}

	vrf := P256Sha256Tai

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := vrf
			gotBeta, err := v.Verify(tt.pk, tt.alpha, tt.pi)
			if (err != nil) != tt.wantErr {
				t.Errorf("vrf.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotBeta, tt.wantBeta) {
				t.Errorf("vrf.Verify() = %v, want %v", gotBeta, tt.wantBeta)
			}
		})
	}
}

type secp256k1gen struct {
	sk    *ecdsa.PrivateKey
	alpha []byte
}

func (secp256k1gen) Generate(rand *rand.Rand, size int) reflect.Value {
	for {
		sk, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			continue
		}
		alpha := make([]byte, rand.Intn(256))
		rand.Read(alpha)
		return reflect.ValueOf(secp256k1gen{sk.ToECDSA(), alpha})
	}
}

type p256gen struct {
	sk    *ecdsa.PrivateKey
	alpha []byte
}

func (p256gen) Generate(rand *rand.Rand, size int) reflect.Value {
	for {
		sk, err := ecdsa.GenerateKey(elliptic.P256(), rand)
		if err != nil {
			continue
		}
		alpha := make([]byte, rand.Intn(256))
		rand.Read(alpha)
		return reflect.ValueOf(p256gen{sk, alpha})
	}
}

func TestRandSkAndAlpha(t *testing.T) {
	t.Run("secp256k1", func(t *testing.T) {
		if err := quick.Check(func(gen secp256k1gen) bool {
			vrf := Secp256k1Sha256Tai
			beta1, pi, err := vrf.Prove(gen.sk, gen.alpha)
			if err != nil {
				return false
			}
			beta2, err := vrf.Verify(&gen.sk.PublicKey, gen.alpha, pi)
			if err != nil {
				return false
			}
			return bytes.Equal(beta1, beta2)
		}, nil); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("p256", func(t *testing.T) {
		if err := quick.Check(func(gen p256gen) bool {
			vrf := P256Sha256Tai
			beta1, pi, err := vrf.Prove(gen.sk, gen.alpha)
			if err != nil {
				return false
			}
			beta2, err := vrf.Verify(&gen.sk.PublicKey, gen.alpha, pi)
			if err != nil {
				return false
			}
			return bytes.Equal(beta1, beta2)
		}, nil); err != nil {
			t.Fatal(err)
		}
	})
}

func BenchmarkVRF(b *testing.B) {
	b.Run("secp256k1sha256tai-proving", func(b *testing.B) {
		sk, _ := secp256k1.GeneratePrivateKey()
		esk := sk.ToECDSA()
		alpha := []byte("Hello VeChain")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := Secp256k1Sha256Tai.Prove(esk, alpha)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("secp256k1sha256tai-verifying", func(b *testing.B) {
		sk, _ := secp256k1.GeneratePrivateKey()
		esk := sk.ToECDSA()
		alpha := []byte("Hello VeChain")

		_, pi, _ := Secp256k1Sha256Tai.Prove(esk, alpha)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := Secp256k1Sha256Tai.Verify(&esk.PublicKey, alpha, pi)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("p256sha256tai-proving", func(b *testing.B) {
		sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.New(rand.NewSource(1)))
		alpha := []byte("Hello VeChain")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := P256Sha256Tai.Prove(sk, alpha)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("p256sha256tai-verifying", func(b *testing.B) {
		sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.New(rand.NewSource(1)))
		alpha := []byte("Hello VeChain")

		_, pi, _ := P256Sha256Tai.Prove(sk, alpha)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := P256Sha256Tai.Verify(&sk.PublicKey, alpha, pi)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// TestNilParameterHandling tests that the VRF functions properly handle nil parameters
func TestNilParameterHandling(t *testing.T) {
	t.Run("Prove with nil private key", func(t *testing.T) {
		vrf := Secp256k1Sha256Tai
		alpha := []byte("test")
		_, _, err := vrf.Prove(nil, alpha)
		if err == nil {
			t.Error("Expected error when private key is nil, got nil")
		}
		expectedMsg := "private key and its fields (D, X, Y) cannot be nil"
		if err.Error() != expectedMsg {
			t.Errorf("Expected '%s', got '%s'", expectedMsg, err.Error())
		}
	})

	t.Run("Prove with nil D field", func(t *testing.T) {
		vrf := Secp256k1Sha256Tai
		alpha := []byte("test")
		sk := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: secp256k1.S256(),
				X:     big.NewInt(1),
				Y:     big.NewInt(1),
			},
			D: nil, // nil D field
		}
		_, _, err := vrf.Prove(sk, alpha)
		if err == nil {
			t.Error("Expected error when private key D is nil, got nil")
		}
		expectedMsg := "private key and its fields (D, X, Y) cannot be nil"
		if err.Error() != expectedMsg {
			t.Errorf("Expected '%s', got '%s'", expectedMsg, err.Error())
		}
	})

	t.Run("Prove with nil X", func(t *testing.T) {
		vrf := Secp256k1Sha256Tai
		alpha := []byte("test")
		sk := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: secp256k1.S256(),
				X:     nil, // nil X
				Y:     big.NewInt(1),
			},
			D: big.NewInt(1),
		}
		_, _, err := vrf.Prove(sk, alpha)
		if err == nil {
			t.Error("Expected error when private key X is nil, got nil")
		}
		expectedMsg := "private key and its fields (D, X, Y) cannot be nil"
		if err.Error() != expectedMsg {
			t.Errorf("Expected '%s', got '%s'", expectedMsg, err.Error())
		}
	})

	t.Run("Prove with nil Y", func(t *testing.T) {
		vrf := Secp256k1Sha256Tai
		alpha := []byte("test")
		sk := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: secp256k1.S256(),
				X:     big.NewInt(1),
				Y:     nil, // nil Y
			},
			D: big.NewInt(1),
		}
		_, _, err := vrf.Prove(sk, alpha)
		if err == nil {
			t.Error("Expected error when private key Y is nil, got nil")
		}
		expectedMsg := "private key and its fields (D, X, Y) cannot be nil"
		if err.Error() != expectedMsg {
			t.Errorf("Expected '%s', got '%s'", expectedMsg, err.Error())
		}
	})

	t.Run("Verify with nil public key", func(t *testing.T) {
		vrf := Secp256k1Sha256Tai
		alpha := []byte("test")
		pi := []byte("fake proof")
		_, err := vrf.Verify(nil, alpha, pi)
		if err == nil {
			t.Error("Expected error when public key is nil, got nil")
		}
		expectedMsg := "public key and its fields (X, Y) cannot be nil"
		if err.Error() != expectedMsg {
			t.Errorf("Expected '%s', got '%s'", expectedMsg, err.Error())
		}
	})

	t.Run("Verify with nil X or Y", func(t *testing.T) {
		vrf := Secp256k1Sha256Tai
		alpha := []byte("test")
		pi := []byte("fake proof")
		pk := &ecdsa.PublicKey{
			Curve: secp256k1.S256(),
			X:     nil, // nil X
			Y:     big.NewInt(1),
		}
		_, err := vrf.Verify(pk, alpha, pi)
		if err == nil {
			t.Error("Expected error when public key X is nil, got nil")
		}
		expectedMsg := "public key and its fields (X, Y) cannot be nil"
		if err.Error() != expectedMsg {
			t.Errorf("Expected '%s', got '%s'", expectedMsg, err.Error())
		}
	})
}

// TestNewWithNilConfig tests that New panics with nil or invalid config
func TestNewWithNilConfig(t *testing.T) {
	t.Run("New with nil config", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when config is nil, got no panic")
			} else if r != "config cannot be nil" {
				t.Errorf("Expected panic 'config cannot be nil', got '%v'", r)
			}
		}()
		New(nil)
	})

	t.Run("New with nil Curve", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when config.Curve is nil, got no panic")
			} else if r != "config.Curve cannot be nil" {
				t.Errorf("Expected panic 'config.Curve cannot be nil', got '%v'", r)
			}
		}()
		New(&Config{
			Curve:       nil,
			SuiteString: 0xfe,
			Cofactor:    0x01,
			NewHasher:   nil,
			Decompress:  nil,
		})
	})
}

func TestVerifyPublicKeyOnCurveValidation(t *testing.T) {
	t.Run("secp256k1 - pk not on curve", func(t *testing.T) {
		vrf := Secp256k1Sha256Tai

		sk, _ := secp256k1.GeneratePrivateKey()
		validPk := sk.PubKey().ToECDSA()

		p := secp256k1.S256().Params().P
		badY := new(big.Int).Mod(new(big.Int).Add(validPk.Y, big.NewInt(1)), p)

		pk := &ecdsa.PublicKey{
			Curve: secp256k1.S256(),
			X:     validPk.X,
			Y:     badY,
		}

		_, err := vrf.Verify(pk, []byte("test"), []byte("fake proof"))
		if err == nil {
			t.Fatal("expected error for public key not on curve, got nil")
		}
		if err.Error() != "public key is not on curve" {
			t.Fatalf("expected 'public key is not on curve', got %q", err.Error())
		}
	})

	t.Run("p256 - pk not on curve", func(t *testing.T) {
		vrf := P256Sha256Tai

		curve := elliptic.P256()
		sk, _ := ecdsa.GenerateKey(curve, rand.New(rand.NewSource(1)))

		p := curve.Params().P
		badY := new(big.Int).Mod(new(big.Int).Add(sk.PublicKey.Y, big.NewInt(1)), p)

		pk := &ecdsa.PublicKey{
			Curve: curve,
			X:     sk.PublicKey.X,
			Y:     badY,
		}

		_, err := vrf.Verify(pk, []byte("test"), []byte("fake proof"))
		if err == nil {
			t.Fatal("expected error for public key not on curve, got nil")
		}
		if err.Error() != "public key is not on curve" {
			t.Fatalf("expected 'public key is not on curve', got %q", err.Error())
		}
	})
}

// TestProvePublicKeyValidation tests that Prove method properly validates public key through validatePublicKey
func TestProvePublicKeyValidation(t *testing.T) {
	t.Run("Prove with public key not on curve - secp256k1", func(t *testing.T) {
		vrf := Secp256k1Sha256Tai

		sk, _ := secp256k1.GeneratePrivateKey()
		validSk := sk.ToECDSA()

		p := secp256k1.S256().Params().P
		badY := new(big.Int).Mod(new(big.Int).Add(validSk.Y, big.NewInt(1)), p)

		badSk := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: secp256k1.S256(),
				X:     validSk.X,
				Y:     badY,
			},
			D: validSk.D,
		}

		_, _, err := vrf.Prove(badSk, []byte("test"))
		if err == nil {
			t.Fatal("expected error for public key not on curve, got nil")
		}
		if err.Error() != "public key is not on curve" {
			t.Fatalf("expected 'public key is not on curve', got %q", err.Error())
		}
	})

	t.Run("Prove with public key not on curve - p256", func(t *testing.T) {
		vrf := P256Sha256Tai

		curve := elliptic.P256()
		sk, _ := ecdsa.GenerateKey(curve, rand.New(rand.NewSource(1)))

		p := curve.Params().P
		badY := new(big.Int).Mod(new(big.Int).Add(sk.PublicKey.Y, big.NewInt(1)), p)

		badSk := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     sk.PublicKey.X,
				Y:     badY,
			},
			D: sk.D,
		}

		_, _, err := vrf.Prove(badSk, []byte("test"))
		if err == nil {
			t.Fatal("expected error for public key not on curve, got nil")
		}
		if err.Error() != "public key is not on curve" {
			t.Fatalf("expected 'public key is not on curve', got %q", err.Error())
		}
	})
}
