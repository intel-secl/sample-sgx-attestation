GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v3.2.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: clean verifier tenantappservice test

verifier:
	cd pkg/tenantverifier && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/version.Version=$(VERSION) -X github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/version.GitHash=$(GITCOMMIT)" -o out/sgx-app-verifier

verifier-installer: verifier
	mkdir -p installer out/
	cp pkg/tenantverifier/out/sgx-app-verifier installer/
	cp pkg/tenantverifier/build/linux/install.sh installer/install.sh && chmod +x installer/install.sh
	makeself installer out/sgx-app-verifier-$(VERSION).bin "sgx-app-verifier $(VERSION)" ./install.sh
	rm -rf installer

tenantappservice: tenantappservice
	cd pkg/tenantappservice && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantappservice/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantappservice/version.Version=$(VERSION) -X github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantappservice/version.GitHash=$(GITCOMMIT)" -o out/sgx-tenant-app-service

tenantappservice-installer: tenantappservice
	mkdir -p installer out/
	cp pkg/tenantappservice/out/sgx-tenant-app-service installer/
	cp pkg/tenantappservice/build/linux/install.sh installer/install.sh && chmod +x installer/install.sh
	cp pkg/tenantappservice/build/linux/libapp.so installer/libapp.so
	cp pkg/tenantappservice/build/linux/libenclave.so installer/libenclave.so
	makeself installer out/sgx-tenant-app-service-$(VERSION).bin "sgx-tenant-app-service $(VERSION)" ./install.sh
	rm -rf installer

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

all: clean verifier-installer tenantappservice-installer test

clean:
	rm -rf out/ installer/
