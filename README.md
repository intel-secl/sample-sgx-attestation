# SGX Attestation Sample Code

The project demonstrates several fundamental usages of Intel(R) Software Guard Extensions (Intel(R) SGX) SDK:

- Initializing and destroying an enclave
- Generate Quote Inside enclave
- Unwrapping secret inside enclave
- Creating a public private key pair inside the enclave and including in the SGX quote a hash of the public key concatenated with a verifier-provided nonce
- Verify the SGX quote and the enclave public keys and the nonce match the hash in the quote
- Generating and sending a Symmetric Wrapping Key (SWK) wrapped with the enclave public key
- Sending a SWK-wrapped secret to the enclave

--------------------------------------------------------------------------------

## 1\. Building the Sample Code

--------------------------------------------------------------------------------

### Pre-requisites

- RHEL 8.0
- GoLang v1.13 or greater
- Intel(R) SGX SDK for Linux
- gcc toolchain
- make
- makeself

- Install Intel(R) SGX SDK for Linux* OS.

- Make sure your environment is set: $ source ${sgx-sdk-install-path}/environment

- You can also refer to quick start guide for 3.2 release.

- <https://github.com/intel-secl/docs/blob/v3.2/develop/quick-start-guides/Quick%20Start%20Guide%20-%20Intel%C2%AE%20Security%20Libraries%20-%20Secure%20Key%20Caching.md>

- Running `make all` build the complete project:

Two installer binaries are created in `out` folder:

- sgx-app-verifier-v*.bin - binary for the verifier app
- sgx-tenantapp-service-v*.bin - binary for the tenant app service

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

Sample configuration

--------------------------------------------------------------------------------

Name               | Type    | Description                                                                                                                                                                                                                                                     | Required Default Value
------------------ | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------
STANDALONE_MODE    | boolean | Sets the operating mode for the verifier service - if set to true will simulate the tenant quote verification quote. The non-standalone mode will be supported in future releases and will pass the quote to an external SGX Quote Verification Service (SQVS). | No                     | true
TENANTSERVICE_HOST | string  | Host on which the tenant app service is deployed                                                                                                                                                                                                                | No                     | 127.0.0.1
TENANTSERVICE_PORT | int     | Listener Port for the tenant app service                                                                                                                                                                                                                        | No                     | 9999
LOG_LEVEL          | string  | Adjust the filter for events info/debug/trace/error                                                                                                                                                                                                             | no                     | info
LOG_MAX_LENGTH     | int     | Maximum length of log entry                                                                                                                                                                                                                                     | No                     | 1500
LOG_ENABLE_STDOUT  | boolean | Logs entries will be printed on stdout                                                                                                                                                                                                                          | No                     |

--------------------------------------------------------------------------------

## 3\. Deploying the Sample Code

--------------------------------------------------------------------------------

### Pre-requisites

- Install Intel(R) SGX SDK for Linux* OS
- Make sure your environment is set: $ source ${sgx-sdk-install-path}/environment
- You can also refer to quick start guide for 3.2 release. <https://github.com/intel-secl/docs/blob/v3.2/develop/quick-start-guides/Quick%20Start%20Guide%20-%20Intel%C2%AE%20Security%20Libraries%20-%20Secure%20Key%20Caching.md>

### SGX Verifier App

1. Place the updated **sgx-tenantapp-service.env** in /root
2. Run the installer binary:

  ```bash
  ./sgx-tenantapp-service-v*.bin
  ```

### SGX Tenant App Service

1. Place the updated **sgx-app-verifier.env** in /root
2. Run the installer binary:

  ```bash
  ./sgx-app-verifier-v*.bin
  ```

--------------------------------------------------------------------------------

## 4\. Running the Sample App Workflow

--------------------------------------------------------------------------------

```bash
# Ensure the tenant app service is running
sgx-tenantapp-service start
```

1. This does the following:
2. Starts the Tenant App Service
3. Initializes the enclave inside the Tenant App
4. Starts the TCP listener on the configured port

```bash
# Get usage information
sgx-tenant-service --help
```

```bash
# Get usage information
sgx-app-verifier --help
```

```bash
# Kick off the quote verification workflow
sgx-app-verifier run
```

These are the components involved:

Component             | Short Name         | Implmented In | Requires SGX for deploy | Requires SGX for build
--------------------- | ------------------ | ------------- | ----------------------- | ----------------------
sgx-app-verifier      | verifier           | Go            | No                      | No
sgx-tenantapp-service | Tenant App Service | Go            | Yes                     | Yes
SGX tenant app        | SGX workload app   | C             | Yes                     | Yes                    |

### Standalone Quote Verification Workflow:

1. The verifier will transmit a CONNECT message to the tenant app service over a TCP socket.
2. The tenant app service, parses the CONNECT request and fetches the quote from the SGX workload running inside the SGX enclave. "The extended quote" is sent back in the response - containing the quote and the enclave's public key.
3. The verifier parses the response, extracts the quote and runs it through the stubbed quote parser and compares a subset of the fields extracted from the quote against those in a hardcoded quote policy file.
4. Once done, the enclave's public key is extracted out of the extended quote, and a symmetric secret wrapping key (SWK) is generated and wrapped using the enclave public key. For StandAlone mode this process is stubbed.
5. This wrapped SWK is sent to the tenant app service, which passes this on to the SGX enclave app. For StanAlone mode this process is stubbed. Only the API call is made. In future release, swk unwrapping will happen in the API call.
6. The enclave app then extracts the SWK out of the payload and responds if it is able to do so. This response is transmitted back to the verifier app. Since the previousstep is stubbed, for standalone mode app don't unwrap the SWK.
7. The verifier app then sends the secret payload wrapped using the SWK to the tenant app service. For StandAlone mode this process is stubbed. Only the API call is made.
8. The tenant app service passes it on to SGX workload inside the enclave. If the secret is unwrapped using the SWK inside the enclave, then the success response is sent back to the verifier app. Since the previous step is stubbed, for standalone mode app don't unwrap the secret.
9. Verifier repeats the entire workflow in the event of a failure at any step and exits when all the steps from 1-8 have completed successfully.
