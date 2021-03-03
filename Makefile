GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v3.2.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

default: all

attestedapplib:
	cd attestedApp/libenclave/ && $(MAKE) all

attestingapplibencrypt:
	cd attestingApp/lib/ && $(MAKE) all

rootcacert:
	mkdir -p out/
	cp *.pem out/

attestingapp: rootcacert attestingapplibencrypt
	cd attestingApp && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/sample-sgx-attestation/v3/attestingApp/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/sample-sgx-attestation/v3/attestingApp/version.Version=$(VERSION) -X github.com/intel-secl/sample-sgx-attestation/v3/attestingApp/version.GitHash=$(GITCOMMIT)" -o ../out/sgx-attesting-app
	cp sgx-quote-policy.txt out/
	cp config.yml.tmpl out/config.yml
attestedapp: attestedapplib
	cd attestedApp && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/version.Version=$(VERSION) -X github.com/intel-secl/sample-sgx-attestation/v3/attestedApp/version.GitHash=$(GITCOMMIT)" -o ../out/sgx-attested-app

attestedapp-installer: attestedapp
	cp attestedApp/libenclave/untrusted.so out/untrusted.so
	cp attestedApp/libenclave/untrusted.so out/untrusted.so
	cp attestedApp/libenclave/enclave.signed.so out/enclave.signed.so

test:
	GOPRIVATE=gitlab.devtools.intel.com/* go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

all: clean  attestingapp attestedapp attestedapplib attestedapp-installer attestingapplibencrypt

clean:
	make -C attestedApp/libenclave/ clean
	rm -rf go.sum out/ cover.*

