# SGX Attestation Sample Code

The project demonstrates several fundamental usages of Intel® Software Guard Extensions (Intel® SGX) SDK:

- Initializing and destroying a SGX enclave hosted in an attestedApp.
- Generate a signed SGX Report and public/private key pair inside the enclave. Add the hash of public key in the signed report.
- Generate a quote using SCS with Intel® DCAP APIs.
- Verify the SGX quote using SGX Quote Verification Service (SQVS) by a separate attestingApp
- Verify that the quote complies with a user-defined quote policy by the attestingApp.
- Generate a Symmetric Wrapping Key (SWK) in the attestingApp, wrap it with enclave's public key and share it with the enclave.
- Exchange encrypted secrets between the attestingApp and the enclave using the SWK.

--------------------------------------------------------------------------------

## 1\. Building the Sample Code

--------------------------------------------------------------------------------

### Pre-requisites

- RHEL 8.2
- GoLang v1.13 or greater
- Intel® SGX SDK for Linux
- gcc toolchain
- make

- Running instance of CMS, SCS and SQVS.
- Install SGX Agent on the host.
- Install Intel® SGX SDK for Linux*OS . Refer [Intel® Software Guard Extensions (Intel® SGX) SDK
for Linux* OS - Installation guide](https://download.01.org/intel-sgx/latest/linux-latest/docs/) . Please install the *-devel for Intel® SGX PSW packages as mentioned in the installation guide.

- Download CA Certificate from CMS

Note : If the deployment is CSP and Enterprise model, use the Enterprise CMS.

```bash
 cd <source folder>
 curl --insecure --location --request GET 'https://<cms.server:port>/cms/v1/ca-certificates' --header 'Accept: application/x-pem-file' > rootca.pem
```

- Update the configuration file at {source folder}/config.yml.tmpl

```yaml
attestedapp-host: 127.0.0.1
attestedapp-port: 9999
sqvs-url: https://<sqvs>:<port>/svs/v1
```

Name             | Type    | Description |
-----------------|---------|--------------|
attestedapp-host | string  | Host on which the attested app service is deployed.|
attestedapp-port | int     | Port where attested app listens for incoming connections.|
sqvs_url         | string  | SQVS URL.|


- Run `make all` to build the project.

Binaries are created in `<source folder>/out`:

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

## 3\. Running the Sample Code

--------------------------------------------------------------------------------

### Pre-requisites

- Make sure your environment is set: $ source ${sgx-sdk-install-path}/environment
- Update /etc/sgx_default_qcnl.conf with SCS IP and port.
- Set includetoken=false in SQVS config.yaml and restart SQVS.

#### Updating attesting App's policy file

- The MREnclave value changes when there is a change in the Enclave. After every change and a build this might need to be updated. 
- Update the policy file at {source folder}/sgx-quote-policy.txt using the template from {source folder}/sgx-quote-policy.txt with the following fields:

```yaml
MREnclave:
MRSigner:
CPU_SVN:
```
- Run the sgx_sign utility to get values of MR Enclave and MR Signer needed by the policy file.

```bash
cd {source folder}
sgx_sign dump -enclave ./attestedApp/libenclave/enclave.signed.so -dumpfile info.txt
```

- In info.txt, search for "mrsigner->value" and add this to "MRSigner:" in /etc/sgx-app-verifier/sgx-quote-policy.txt.
- In info.txt, search for "metadata->enclave_css.body.enclave_hash.m:" and add this to "MREnclave:" in /etc/sgx-app-verifier/sgx-quote-policy.txt
- E.g : In info.txt  mrsigner->value: "0x83 0xd7 0x19 0xe7 0x7d 0xea 0xca 0x14 0x70 0xf6 0xba 0xf6 0x2a 0x4d 0x77 0x43 0x03 0xc8 0x99 0xdb 0x69 0x02 0x0f 0x9c 0x70 0xee 0x1d 0xfc 0x08 0xc7 0xce 0x9e" needs to be added as "MRSigner:83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e" in sgx-quote-policy.txt . Remove '0x' and spaces. Same applies for MREnclave.
- Contents of a good sgx-quote-policy.txt file would look like : 

```yaml
MREnclave:c80de12554feb664496c59f708954aca1572a8cf60f2184f99857081b6314bb8
MRSigner:83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
CPU_SVN:00
```
- Run `make all`. This would copy the policy file and the config.yml to {source folder}/out

### SGX Attested App

- Make sure your environment is set: $ source ${sgx-sdk-install-path}/environment
- Run the Attested App binary first in a new terminal:

  ```bash
  cd {source folder}/out/
  ./sgx-attested-app run
  ```
- This initializes the enclave inside the Attested App and starts the TCP listener on the configured port.

### SGX Attesting App

- Make sure your environment is set: $ source ${sgx-sdk-install-path}/environment
- Run the Attesting App binary in a new terminal:

  ```bash
   cd <source folder>/out/
  ./sgx-attesting-app run
  ```

These are the components involved:

Component             | Short Name         | Implmented In | Requires SGX for deploy | Requires SGX for build
--------------------- | ------------------ | ------------- | ----------------------- | ----------------------
sgx-attesting-app      | verifier           | Go            | No                      | No
sgx-attested-app | Attested App Service | Go            | Yes                     | Yes
libenclave      | SGX Enclave Workload           | C/C++            | Yes                      | Yes

### Quote Verification and Secret Provisioning Workflow:

1. The attestingApp will transmit a CONNECT message to the attestedApp service over a TCP socket.
2. The attestedApp service, parses the CONNECT request and fetches the enclave's SGX quote. "The extended quote" is sent back in the response - containing the quote and the enclave's public key.
3. The attestingApp parses the response, extracts the quote and verifies it with SQVS and compares a subset of the fields extracted from the quote against those in a hardcoded quote policy file.
4. The enclave's public key is extracted out of the extended quote, and a symmetric secret wrapping key (SWK) is generated and wrapped using the enclave public key.
5. The attestingApp ensures that the public key has been generated in the enclave by comparing its hash to the hash included in the quote.
6. The wrapped SWK is sent to the attestedApp, which inturn passes it to the SGX enclave.
7. The enclave then extracts the SWK out of the payload and responds if it is able to do so. This response is transmitted back to the attestingApp.
8. The attestingApp then sends the secret payload wrapped using the SWK to the attestedApp service.
9. The attestedApp service passes it on to SGX workload inside the enclave. If the secret is unwrapped using the SWK inside the enclave, then the success response is sent back to the attestingApp.
