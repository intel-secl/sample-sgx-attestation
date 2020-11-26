GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v3.2.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

default: all

tenantapp:
	cd tenantApp/ && $(MAKE) all

verifier:
	cd pkg/tenantverifier && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/version.Version=$(VERSION) -X github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantverifier/version.GitHash=$(GITCOMMIT)" -o out/sgx-app-verifier

verifier-installer: verifier
	mkdir -p installer out/
	cp pkg/tenantverifier/out/sgx-app-verifier installer/
	cp pkg/tenantverifier/build/linux/install.sh installer/install.sh && chmod +x installer/install.sh
	cp pkg/tenantverifier/build/linux/sgx-quote-policy.txt installer/sgx-quote-policy.txt
	makeself installer out/sgx-app-verifier-$(VERSION).bin "sgx-app-verifier $(VERSION)" ./install.sh
	rm -rf installer

tenantappservice: tenantapp
	cd pkg/tenantappservice && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantappservice/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantappservice/version.Version=$(VERSION) -X github.com/intel-secl/sample-sgx-attestation/v3/pkg/tenantappservice/version.GitHash=$(GITCOMMIT)" -o out/sgx-tenantapp-service

tenantappservice-installer: tenantappservice
	mkdir -p installer out/
	cp pkg/tenantappservice/out/sgx-tenantapp-service installer/
	cp pkg/tenantappservice/build/linux/install.sh installer/install.sh && chmod +x installer/install.sh
	cp pkg/tenantappservice/build/linux/sgx-tenantapp-service.service installer/sgx-tenantapp-service.service
	cp tenantApp/app.so installer/app.so
	cp tenantApp/enclave.signed.so installer/enclave.signed.so
	makeself installer out/sgx-tenantapp-service-$(VERSION).bin "sgx-tenantapp-service $(VERSION)" ./install.sh
	rm -rf installer

test:
	GOPRIVATE=gitlab.devtools.intel.com/* go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

all: clean tenantapp verifier-installer tenantappservice-installer

clean:
	make -C tenantApp clean
	rm -rf go.sum out/ installer/ pkg/tenantappservice/out pkg/tenantverifier/out cover.*

