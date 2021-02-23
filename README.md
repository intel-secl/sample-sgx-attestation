# SGX Attestation Sample Code

The project demonstrates several fundamental usages of Intel(R) Software Guard Extensions (Intel(R) SGX) SDK:

- Initializing and destroying an enclave
- Generate Quote Inside enclave
- Creating a public private key pair inside the enclave and including in the SGX quote a hash of the public key concatenated with a verifier-provided nonce
- Verify the SGX quote 

--------------------------------------------------------------------------------

## 1\. Building the Sample Code

--------------------------------------------------------------------------------

### Pre-requisites

- RHEL 8.0
- GoLang v1.13 or greater
- Intel(R) SGX SDK for Linux
- gcc toolchain
- make

- Install Intel(R) SGX SDK for Linux* OS.

- Make sure your environment is set: $ source ${sgx-sdk-install-path}/environment

- Running `make all` will build the project.

Binaries are created in `attestedApp/out` and `attestingApp/out` folder:

- sgx-attesting-app - binary for the Attesting App
- sgx-attested-app- binary for the Attested App.

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

- Install Intel(R) SGX SDK for Linux* OS
- Make sure your environment is set: $ source ${sgx-sdk-install-path}/environment
- Update /etc/sgx_default_qcnl.conf with SCS IP and port.
- Set SQVS_INCLUDE_TOKEN=false in SQVS config.yaml and restart SQVS.
- Download CA Certificate from CMS

```bash
 cd <source root folder>
 curl --insecure --location --request GET 'https://<cms.server:port>/cms/v1/ca-certificates' --header 'Accept: application/x-pem-file' > rootca.pem
```

#### Updating attesting App's policy file

- Run the sgx_sign utility to get information on MR Enclave and MR Signer needed by the offline policy file.

```bash
cd <source root folder>
sgx_sign dump -enclave ./attestedApp/lib/enclave.signed.so -dumpfile info.txt
```
- In info.txt. search for "mrsigner->value" and add this to "MRSigner:" in the build/linux/sgx-quote-policy.txt.
- In info.txt, search for "metadata->enclave_css.body.enclave_hash.m:" and add this to "MREnclave:" in the build/linix/sgx-quote-policy.txt

### SGX Attested

1. Update ./attestedApp/out/config.yml 
2. Run the Attested App binary:

  ```bash
  ./sgx-attested-app run
  ```

3. Initializes the enclave inside the Tenant App
4. Starts the TCP listener on the configured port

### SGX Attesting App

1. Update ./attestingApp/out/config.yml 
2. Run the Attesting App binary:

  ```bash
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
   