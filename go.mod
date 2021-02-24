module github.com/intel-secl/sample-sgx-attestation/v3

require (
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.5.0
	github.com/spf13/cast v1.3.0
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.6.1
	gopkg.in/yaml.v2 v2.3.0
	intel/isecl/lib/common/v3 v3.3.1
)


replace intel/isecl/lib/common/v3 => github.com/intel-secl/common/v3 v3.3.1
replace intel/isecl/lib/clients/v3 => github.com/intel-secl/clients/v3 v3.3.1
