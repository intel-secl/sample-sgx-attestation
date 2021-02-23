GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v3.2.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

default: all

attestedapplib:
	cd attestedApp/lib/ && $(MAKE) all

rootcacert:
	mkdir -p attestingApp/out/
	cp *.pem attestingApp/out/

attestingapp: rootcacert
	cd attestingApp && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/sample-sgx-attestation/v3/attestingApp/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/sample-sgx-attestation/v3/attestingApp/version.Version=$(VERSION) -X github.com/intel-secl/sample-sgx-attestation/v3/attestingApp/version.GitHash=$(GITCOMMIT)" -o out/sgx-attesting-app
	cp attestingApp/build/linux/sgx-quote-policy.txt attestingApp/out/
	cp attestingApp/build/linux/sgx-app-verifier.env attestingApp/out/
	cp attestingApp/config.yml.tmpl attestingApp/out/config.yml
attestedapp: attestedapplib
	cd attestedApp && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/version.Version=$(VERSION) -X github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/version.GitHash=$(GITCOMMIT)" -o out/sgx-attested-app

attestedapp-installer: attestedapp
	cp attestedApp/lib/untrusted.so attestedApp/out/untrusted.so
	cp attestedApp/lib/enclave.signed.so attestedApp/out/enclave.signed.so

test:
	GOPRIVATE=gitlab.devtools.intel.com/* go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

all: clean  attestingapp attestedapp attestedapplib attestedapp-installer

clean:
	make -C attestedApp/lib/ clean
	rm -rf go.sum out/ attestedApp/out attestingApp/out cover.*

