GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: installer test all clean

sgx-app-verifier:
	GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/sample-sgx-attestation/v3/tenantverifier/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/sample-sgx-attestation/v3/tenantverifier/version.Version=$(VERSION) -X github.com/intel-secl/sample-sgx-attestation/v3/tenantverifier/version.GitHash=$(GITCOMMIT)" -o out/sgx-app-verifier

installer: sgx-app-verifier
	cp build/linux/sgx-app-verifier.service out/sgx-app-verifier.service
	cp build/linux/install.sh out/install.sh && chmod +x out/install.sh
	makeself out out/sgx-app-verifier-$(VERSION).bin "sgx-app-verifier $(VERSION)" ./install.sh
	rm -rf installer

sgx-tenant-service:
	GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/sample-sgx-attestation/v3/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/sample-sgx-attestation/v3/version.Version=$(VERSION) -X github.com/intel-secl/sample-sgx-attestation/v3/version.GitHash=$(GITCOMMIT)" -o out/sgx-app-verifier

installer: sgx-app-verifier
	cp build/linux/sgx-app-verifier.service out/sgx-app-verifier.service
	cp build/linux/install.sh out/install.sh && chmod +x out/install.sh
	makeself out out/sgx-app-verifier-$(VERSION).bin "sgx-app-verifier $(VERSION)" ./install.sh
	rm -rf installer

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

all: clean installer test

clean:
	rm -rf out/
