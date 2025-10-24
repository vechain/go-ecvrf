FUZZTIME=1m

.PHONY: fuzz test

fuzz:
	go test -fuzz=FuzzSecp256k1Sha256TaiProve -fuzztime=$(FUZZTIME)
	go test -fuzz=FuzzSecp256k1Sha256TaiVerify -fuzztime=$(FUZZTIME)
	go test -fuzz=FuzzP256Sha256TaiProve -fuzztime=$(FUZZTIME)
	go test -fuzz=FuzzP256Sha256TaiVerify -fuzztime=$(FUZZTIME)

test:
	go test ./...