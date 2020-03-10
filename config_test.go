// Copyright (c) 2020 vechain.org.
// Licensed under the MIT license.

package ecvrf

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestDefaultSqrt(t *testing.T) {
	type args struct {
		c elliptic.Curve
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"p256",
			args{
				elliptic.P256(),
				"23641628374218637252523134409825450466172496366265976434932954203032325458800",
			},
			"108980937802188484198425629766080801309523465968363373048763527645240613153665",
		},
		{
			"p256 invalid",
			args{
				elliptic.P256(),
				"23641628374218637252523134409825450466172496366265976434932954203032325458801",
			},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := new(big.Int)
			s.UnmarshalText([]byte(tt.args.s))

			got := DefaultSqrt(tt.args.c, s)
			gotStr := ""
			if got != nil {
				gotStr = got.String()
			}

			if gotStr != tt.want {
				t.Errorf("DefaultSqrt() = %v, want %v", gotStr, tt.want)
			}
		})
	}
}
