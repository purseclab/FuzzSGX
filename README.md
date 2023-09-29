# FuzzSGX
**FuzzSGX** is a fuzzer for Intel SGX SDK enclaves. It is brought to you by the folks at [Pursec Lab](https://pursec.cs.purdue.edu/). For queries, either use GitHub issues (preferred method), or email the authors: 

[Arslan Khan](mailto:khan253@purdue.edu?subject=[GitHub]%20Source%20Han%20Sans)

[Muqi Zou](mailto:zou116@purdue.edu?subject=[GitHub]%20Source%20Han%20Sans)


## FuzzSGX dependencies:
FuzzSGX is written on top of the following tools:
1. Python 2.7 (We plan to update since angr no longer supports this)
2. Angr 7.8.9.26 (This is an old version that supports Python 2.7)
3. Intel SGX SDK v2.10
4. AFL++ (afl-fuzz++2.65d, but ideally should work with all families of afl)

Please see the corresponding projects for installation details. Feel free to ask any questions about installation of any of the projects.

## FuzzSGX Source Code Details.
FuzzSGX is highly modular and uses existing tools as much as it can. For the framework's internals, please look at our [Euro S&P submission](https://ieeexplore.ieee.org/document/10190488). The source code is organized into three big submodules:

1. Fuzzer: The main driver that utilizes both input and program mutations)
2. LLVM: Static analyses required for extracting program dependencies, such as chain dependencies)
3. LibFuzzSGX: The core LibOS that enables fuzzing in Intel SGX enclaves using cross-enclave calls.
4. examples: Example projects, that ideally should run out of the box. 

To highlight the modularity of the project, each component is standalone and can be used without others. For instance, LibFuzzSGX enables fuzzing inside the enclaves and can be used only with the AFL family of fuzzers, if program mutation is not required. Similarly, the program mutation fuzzer is not dependent on the LLVM static analysis results and if required those results can run without that information. 

## FuzzSGX How to run:
The easiest way is to just run the example project. 
1. Clone, Install dependencies, and then go to examples folders. For this guide, we will use the wolfssl project.
  ```cd ./examples/wolfssl/wolfssl-examples/SGX_Linux```
2. Set up environment.
   ``` source ./env_AFL  ```
3. There is a helper make script that can run the fuzzer. Just invoke:
   ``` make modeld ```
   This will take some time in doing symbolic execution and parsing, and then start input mutation using AFL++. Periodically the fuzzer will trigger program mutation to generate a new harness. 


## Supporting a new project:
TODO: Will add this soon too. 


