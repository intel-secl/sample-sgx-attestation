module github.com/intel-secl/sample-sgx-attestation/v3

require (
	github.com/intel-secl/intel-secl/v3 v3.2.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.5.0
	github.com/spf13/cast v1.3.0
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.6.1
	gopkg.in/yaml.v2 v2.3.0
	intel/isecl/lib/common/v3 v3.3.0
	intel/isecl/sqvs/v3 v3.3.0
)

replace intel/isecl/lib/common/v3 => gitlab.devtools.intel.com/sst/isecl/lib/common.git/v3 v3.3/develop

replace github.com/intel-secl/intel-secl/v3 => gitlab.devtools.intel.com/sst/isecl/intel-secl.git/v3 v3.3/develop

replace intel/isecl/sqvs/v3 => gitlab.devtools.intel.com/sst/isecl/sgx-verification-service.git/v3 v3.3/develop

replace intel/isecl/lib/clients/v3 => gitlab.devtools.intel.com/sst/isecl/lib/clients.git/v3 v3.3/develop

