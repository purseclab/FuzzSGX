------------------------
libFuzzSGX
------------------------
The project provides a framework for fuzzing Intel SGX enclaves in 
simulation mode. Currently by design enclaves are not allowed to. 
LibSGXFuzz can be seen as alibrary OS, that fulfills the dependencies 
for the following:

- Sanitizers
- American Fuzz Lop 

Unlike existing SGX projects we care more about efficiency than secrecy. 
This is to have as many executions as possible. Our architecture is 
loosely based on libSGXFuzz Library. 

----------------------
System Requirements
-------------------
libFuzzSGX requires:

- Intel SGX SDK 
- Ubuntu 18.04 (Current implementation is tested on this platform, 
however we reckon it should work on other platforms as well)


-------------------
Building libFuzzSGX
-------------------

1. cd "root-of-libFuzzSGX-repo"
2. make

Successful copmilation should generate libsgx_tsgxfuzz.a and 
libsgx_usgxfuzz.a in the root directory.


----------------------------------------
How to fuzz your project with libFuzzSGX
----------------------------------------
1. Make sure your environment is set:
    $ source ${sgx-sdk-install-path}/environment
2. In your EDL file add:
    from "libsgx_tsgxfuzz.edl" import *;
3. To the sgx_edger8r command running on your enclave 
EDL file for generating either trusted or
untrusted proxy and bridge routines, add the path to the libsgx_tsgxfuzz.edl
with the --search-path option. 

In the Enclave project, use the following steps to set up the environment for the libSGXFuzz.
1. Use -L flag to provide the linker with the path to the trusted library "libsgx_tsgxfuzz".
Add this to your enclave link flags.
	-L$(LIB_SFUZZ)
where LIB_SFUZZ is the root of libSGXFuzz repo.
2. Use -Wl,--whole-archive -lsgx_tsgxfuzz -Wl,--no-whole-archive to link with 
the trusted archive.
3. Use -I compilation flag to specify the path to the SGX Fuzz header files, like -
I$(LIB_SFUZZ)/Inclue

In the Application project, use the following steps to set up the environment for the libSGXFuzz
library: 

1. Use -L flag to provide the linker with the path to the untrusted SGX Fuzz library
libsgx_usgxfuzz.a, with -L$(LIB_SFUZZ)
2. Use -lsgx_usgxfuzz to provide the linker with the names of libSGXFuzzz untrusted libraries.

