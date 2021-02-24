# SGX Attestation Sample Code

The project demonstrates several fundamental usages of Intel(R) Software Guard Extensions (Intel(R) SGX) SDK:

- Initializing and destroying an enclave
- Generate Quote Inside enclave
- Creating a public/private key pair inside the enclave and including the hash of public key in the SGX quote
- Verify the SGX quote using SGX Quote Verification Service (SQVS)

--------------------------------------------------------------------------------

## 1\. Building the Sample Code

--------------------------------------------------------------------------------

### Pre-requisites

- RHEL 8.2
- GoLang v1.13 or greater
- Intel(R) SGX SDK for Linux
- gcc toolchain
- make

- Running instance of CMS, SCS and SQVS.
- Install SGX Agent on the host.
- Install Intel(R) SGX SDK for Linux* OS . Refer [Intel® Software Guard Extensions (Intel® SGX) SDK
for Linux* OS - Installation guide](https://download.01.org/intel-sgx/latest/linux-latest/docs/)

- Download CA Certificate from CMS

```bash
 cd <source folder>
 curl --insecure --location --request GET 'https://<cms.server:port>/cms/v1/ca-certificates' --header 'Accept: application/x-pem-file' > rootca.pem
```

- Create a configuration file at /etc/sgx-tenantapp-service/config.yml and add the following fields 
```yaml
tenantservice-host: 127.0.0.1
tenantservice-port: 9999
log:
  max-length: 1500
  enable-stdout: true
  level: info
```

- Update the configuration file at {source folder}/attestingApp/config.yml.tmpl

```yaml
tenantservice-host: 127.0.0.1
tenantservice-port: 9999
sqvs-url: https://<sqvs>:<port>/svs/v1
server:
  read-timeout: 30s
  read-header-timeout: 10s
  write-timeout: 30s
  idle-timeout: 10s
  max-header-bytes: 1048576
log:
  max-length: 1500
  enable-stdout: true
  level: info
```

- Run `make all` to build the project.

Binaries are created in `attestedApp/out` and `attestingApp/out` folder:

- sgx-attesting-app - binary for the Attesting App
- sgx-attested-app - binary for the Attested App.

--------------------------------------------------------------------------------

## 2\. Configuration Parameters For Enclave

--------------------------------------------------------------------------------

For a dynamically created thread:

Param        | Description
------------ | ------------------------------------------------------------------------------
StackMaxSize | Total amount of stack memory that enclave thread can use.
StackMinSize | Minimum amount of stack memory available to the enclave thread after creation.

The gap between StackMinSize and StackMaxSize is the stack dynamically expanded as necessary at runtime.

For a static thread, only StackMaxSize is relevant which specifies the total amount of stack available to the thread.

Param        | Description
------------ | --------------------------------------------------------
HeapMaxSize  | Total amount of heap an enclave can use.
HeapInitSize | Added for compatibility.
HeapMinSize  | Amount of heap available once the enclave is initialized

The different between HeapMinSize and HeapMaxSize is the heap memory. This is adjusted dynamically as required at runtime.

--------------------------------------------------------------------------------

Sample configuration (config.yml)

--------------------------------------------------------------------------------

Name               | Type    | Description                                                                                                                                                                                                                                                     | Required Default Value
------------------ | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------
tenantservice-host | string  | Host on which the tenant app service is deployed                                                                                                                                                                                                                | No                     | 127.0.0.1
tenantservice-port | int     | Listener Port for the tenant app service                                                                                                                                                                                                                        | No                     | 9999
sqvs_url | int     | Listener Port for the tenant app service                                                                                                                                                                                                                        | No                     | 9999

--------------------------------------------------------------------------------

## 3\. Running the Sample Code

--------------------------------------------------------------------------------

### Pre-requisites

- Make sure your environment is set: $ source ${sgx-sdk-install-path}/environment
- Update /etc/sgx_default_qcnl.conf with SCS IP and port.
- Set SQVS_INCLUDE_TOKEN=false in SQVS config.yaml and restart SQVS.

#### Updating attesting App's policy file

- Create a policy file yaml file at /etc/sgx-app-verifier/sgx-quote-policy.txt using the template from <source folder>/attestingApp/build/linux/sgx-quote-policy.txt with the following fields
```yaml
MREnclave:
MRSigner:
CPU_SVN:
```
- Run the sgx_sign utility to get information on MR Enclave and MR Signer needed by the offline policy file.

```bash
cd <source folder>
sgx_sign dump -enclave ./attestedApp/lib/enclave.signed.so -dumpfile info.txt
```
- In info.txt, search for "mrsigner->value" and add this to "MRSigner:" in /etc/sgx-app-verifier/sgx-quote-policy.txt.
- In info.txt, search for "metadata->enclave_css.body.enclave_hash.m:" and add this to "MREnclave:" in /etc/sgx-app-verifier/sgx-quote-policy.txt
- In info.txt , mrsigner->value: "0x83 0xd7 0x19 0xe7 0x7d 0xea 0xca 0x14 0x70 0xf6 0xba 0xf6 0x2a 0x4d 0x77 0x43 0x03 0xc8 0x99 0xdb 0x69 0x02 0x0f 0x9c 0x70 0xee 0x1d 0xfc 0x08 0xc7 0xce 0x9e" needs to be added as "MRSigner:83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e" in sgx-quote-policy.txt . Same applies for MREnclave.
- E.g /etc/sgx-app-verifier/sgx-quote-policy.txt : 
```yaml
MREnclave:c80de12554feb664496c59f708954aca1572a8cf60f2184f99857081b6314bb8
MRSigner:83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
CPU_SVN:00
```

### SGX Attested App
- Make sure your environment is set: $ source ${sgx-sdk-install-path}/environment
- Run the Attested App binary first in a new terminal:

  ```bash
  cd <source folder>/attestedApp/out/
  ./sgx-attested-app run
  ```

- This initializes the enclave inside the Tenant App
- And starts the TCP listener on the configured port

### SGX Attesting App
- Make sure your environment is set: $ source ${sgx-sdk-install-path}/environment
- Run the Attesting App binary in a new terminal:

  ```bash
   cd <source folder>/attestingApp/out/
  ./sgx-attesting-app run
  ```


These are the components involved:

Component             | Short Name         | Implmented In | Requires SGX for deploy | Requires SGX for build
--------------------- | ------------------ | ------------- | ----------------------- | ----------------------
sgx-attesting-app      | verifier           | Go            | No                      | No
sgx-attested-app | Tenant App Service | Go            | Yes                     | Yes
attestedApp/        | SGX workload       | C             | Yes                     | Yes                    |

### Quote Verification Workflow:

1. The attestingApp will transmit a CONNECT message to the attestedApp service over a TCP socket.
2. The attestedApp service, parses the CONNECT request and fetches the quote from the SGX workload running inside the SGX enclave. "The extended quote" is sent back in the response - containing the quote and the enclave's public key.
3. The attestingApp parses the response, extracts the quote and verifies it with SQVS and compares a subset of the fields extracted from the quote against those in a hardcoded quote policy file.
4. The enclave's public key is extracted out of the extended quote, and a symmetric secret wrapping key (SWK) is generated and wrapped using the enclave public key. 
5. This wrapped SWK is sent to the attestedApp, which inturn passes it to the SGX enclave app. 
6. The enclave then extracts the SWK out of the payload and responds if it is able to do so. This response is transmitted back to the attestingApp. 
7. The attestingApp then sends the secret payload wrapped using the SWK to the attestedApp service.
8. The attestedApp service passes it on to SGX workload inside the enclave. If the secret is unwrapped using the SWK inside the enclave, then the success response is sent back to the attestingApp. 
   