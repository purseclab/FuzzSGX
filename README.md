# FuzzSGX
**FuzzSGX** is a fuzzer for Intel SGX SDK enclaves. It is brought to you by the folks at [Pursec Lab](https://pursec.cs.purdue.edu/). For queries, either use GitHub issues (preferred method), or email the authors: 

[Arslan Khan](mailto:khan253@purdue.edu?subject=[GitHub]%20Source%20Han%20Sans)

[Muqi Zou](mailto:zou116@purdue.edu?subject=[GitHub]%20Source%20Han%20Sans)


## FuzzSGX dependencies:

## FuzzSGX Source Code Details.
FuzzSGX is highly modular and uses existing tools as much as it can. For the framework's internals, please look at our [Euro S&P submission](https://ieeexplore.ieee.org/document/10190488). The source code is organized into three big submodules:

1. Fuzzer: The main driver that utilizes both input and program mutations)
2. LLVM: Static analyses required for extracting program dependencies, such as chain dependencies)
3. LibFuzzSGX: The core LibOS that enables fuzzing in Intel SGX enclaves using cross-enclave calls.
4. examples: Example projects, that ideally should run out of the box. 

To highlight the modularity of the project, each component is standalone and can be used without others. For instance, LibFuzzSGX enables fuzzing inside the enclaves and can be used only with the AFL family of fuzzers, if program mutation is not required. Similarly, the program mutation fuzzer is not dependent on the LLVM static analysis results and if required those results can run without that information. 
