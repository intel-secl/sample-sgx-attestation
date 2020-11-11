-------------------------------
Purpose of SampleSGXAttestation
-------------------------------
The project demonstrates several fundamental usages of Intel(R) Software Guard 
Extensions (Intel(R) SGX) SDK:
- Initializing and destroying an enclave
- Generate Quote Inside enclave
- Unwrapping secret inside enclave
- Creating Public Key inside enclave
- Verify the quote generated. Extract Public key from encalve
- Send a key wrapped in public key to enclave to unwrap
- Send secret wrapped in wrapped ket to be unwrapped in enclave

------------------------------------
How to Build/Deploy the Sample Code
------------------------------------
1. Install Intel(R) SGX SDK for Linux* OS
2. Build the project with the prepared Makefile:
		a)Run make all
		b) two golang installers are created in out folder:
			i)<verifier>
			ii)<app server>


------------------------------------
How to Deploy the Sample Code
------------------------------------
3. For Deployment:
		TODO: <add here>
4. For execution
		TODO:<add here>

-------------------------------------------------------
Explanation about Configuration Parameters For Enclave
-------------------------------------------------------
StackMaxSize, StackMinSize

    For a dynamically created thread, StackMinSize is the amount of stack available
    once the thread is created and StackMaxSize is the total amount of stack that
    thread can use. The gap between StackMinSize and StackMaxSize is the stack
    dynamically expanded as necessary at runtime.

    For a static thread, only StackMaxSize is relevant which specifies the total
    amount of stack available to the thread.


HeapMaxSize, HeapInitSize, HeapMinSize

    HeapMinSize is the amount of heap available once the enclave is initialized.

    HeapMaxSize is the total amount of heap an enclave can use. The gap between
    HeapMinSize and HeapMaxSize is the heap dynamically expanded as necessary
    at runtime.

    HeapInitSize is here for compatibility.

-------------------------------------------------    
Sample configuration files for the Sample SKC Attestation App
-------------------------------------------------
