FUZZTIME=1m

.PHONY: fuzz test

fuzz:
	@go test -fuzz=FuzzProveVerifySecp256k1 -fuzztime=$(FUZZTIME)
	@go test -fuzz=FuzzProveVerifyP256 -fuzztime=$(FUZZTIME)
	@go test -fuzz=FuzzDecodeProofSecp256k1 -fuzztime=$(FUZZTIME)
	@go test -fuzz=FuzzDecodeProofP256 -fuzztime=$(FUZZTIME)
	@go test -fuzz=FuzzHashToCurveTryAndIncrementSecp256k1 -fuzztime=$(FUZZTIME)
	@go test -fuzz=FuzzHashToCurveTryAndIncrementP256 -fuzztime=$(FUZZTIME)
	@go test -fuzz=FuzzProveVerifyRandomKeysSecp256k1 -fuzztime=$(FUZZTIME)
	@go test -fuzz=FuzzProveVerifyRandomKeysP256 -fuzztime=$(FUZZTIME)

test:
	@go test ./...