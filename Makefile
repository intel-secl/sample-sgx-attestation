GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v3.2.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: clean verifier tenantapp test

verifier:
	cd pkg/tenantverifier && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/sample-sgx-attestation/v3/tenantverifier/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/sample-sgx-attestation/v3/tenantverifier/version.Version=$(VERSION) -X github.com/intel-secl/sample-sgx-attestation/v3/tenantverifier/version.GitHash=$(GITCOMMIT)" -o out/sgx-app-verifier

verifier-installer: verifier
	mkdir -p installer out/
	cp pkg/tenantverifier/out/sgx-app-verifier installer/
	cp build/linux/install.sh installer/install.sh && chmod +x installer/install.sh
	cp build/linux/libapp.so installer/libapp.so
	makeself installer out/sgx-app-verifier-$(VERSION).bin "sgx-app-verifier $(VERSION)" ./install.sh
	rm -rf installer

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

all: clean verifier-installer test

clean:
	rm -rf out/ installer/
