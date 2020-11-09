GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)


GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v3.2.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: clean verifier tenantapp1 tenantapp test
#.PHONY: clean tenantapp1 tenantapp

verifier:
	cd pkg/tenantverifier && env GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/sample-sgx-attestation/v3/tenantverifier/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/sample-sgx-attestation/v3/tenantverifier/version.Version=$(VERSION) -X github.com/intel-secl/sample-sgx-attestation/v3/tenantverifier/version.GitHash=$(GITCOMMIT)" -o out/sgx-app-verifier

verifier-installer: verifier
	mkdir -p installer out/
	cp pkg/tenantverifier/out/sgx-app-verifier installer/
	cp pkg/tenantverifier/build/linux/sgx-app-verifier.service installer/sgx-app-verifier.service
	cp pkg/tenantverifier/build/linux/install.sh installer/install.sh && chmod +x installer/install.sh
	makeself installer out/sgx-app-verifier-$(VERSION).bin "sgx-app-verifier $(VERSION)" ./install.sh
	rm -rf installer

tenantapp1:
	cd tenantApp && make all

tenantapp:
	cd pkg/tenantapp && envGOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/sample-sgx-attestation/v3/tenantapp/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/sample-sgx-attestation/v3/tenantapp/version.Version=$(VERSION) -X github.com/intel-secl/sample-sgx-attestation/v3/tenantapp/version.GitHash=$(GITCOMMIT)" -o out/sgx-tenant-app

tenantapp-installer: tenantapp
	mkdir -p installer out/
	cp pkg/tenantapp/out/sgx-tenant-app installer/
	cp pkg/tenantapp/build/linux/sgx-tenant-app.service installer/sgx-tenant-app.service
	cp pkg/tenantapp/build/linux/install.sh installer/install.sh && chmod +x installer/install.sh
	makeself installer out/sgx-tenant-app-$(VERSION).bin "sgx-tenant-app $(VERSION)" ./install.sh
	rm -rf installer

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

all: clean verifier-installer tenantapp1 tenantapp-installer test

clean:
	rm -rf out/ installer/
	cd tenantApp && make clean
