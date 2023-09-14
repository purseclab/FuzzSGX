include bitcode.mk
all: pass bitcode run

.PHONY: all
pass:
	/usr/bin/c++  -DGTEST_HAS_RTTI=0 -D_DEBUG -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS -I/home/arslan/Documents/LBC/rustc/rust/build/x86_64-unknown-linux-gnu/llvm/build/lib/Transforms/IOSanitizer -I/home/arslan/Documents/LBC/rustc/rust/src/llvm-project/llvm/lib/Transforms/IOSanitizer -I/home/arslan/Documents/LBC/rustc/rust/build/x86_64-unknown-linux-gnu/llvm/build/include -I/home/arslan/Documents/LBC/rustc/rust/src/llvm-project/llvm/include  -ffunction-sections -fdata-sections -fPIC -m64 -fPIC -fvisibility-inlines-hidden -Werror=date-time -std=c++11 -Wall -Wextra -Wno-unused-parameter -Wwrite-strings -Wcast-qual -Wno-missing-field-initializers -pedantic -Wno-long-long -Wimplicit-fallthrough -Wno-maybe-uninitialized -Wno-noexcept-type -Wdelete-non-virtual-dtor -Wno-comment -g -fPIC    -fno-exceptions -fno-rtti -o ./iosan.cpp.o -c /home/arslan/Documents/LBC/rustc/rust/src/llvm-project/llvm/lib/Transforms/IOSanitizer/iosan.cpp && /usr/bin/c++ -fPIC -ffunction-sections -fdata-sections -fPIC -m64 -fPIC -fvisibility-inlines-hidden -Werror=date-time -std=c++11 -Wall -Wextra -Wno-unused-parameter -Wwrite-strings -Wcast-qual -Wno-missing-field-initializers -pedantic -Wno-long-long -Wimplicit-fallthrough -Wno-maybe-uninitialized -Wno-noexcept-type -Wdelete-non-virtual-dtor -Wno-comment -g  -Wl,-rpath-link,/home/arslan/Documents/LBC/rustc/rust/build/x86_64-unknown-linux-gnu/llvm/build/./lib   -Wl,--version-script,"/home/arslan/Documents/LBC/rustc/rust/build/x86_64-unknown-linux-gnu/llvm/build/lib/Transforms/IOSanitizer/LLVMIOSan.exports"  -Wl,-z,nodelete -shared  -o ./LLVMIOSan.so ./iosan.cpp.o -Wl,-rpath,"\$ORIGIN/../lib"

bitcode:
	make -C ~/sgxsdk2/sgxsdk/SampleCode/SampleEnclave
	cp ~/sgxsdk2/sgxsdk/SampleCode/SampleEnclave/uniq_interface.data .

run:
	/home/arslan/Documents/LBC/rustc/rust/rust_ws/../build/x86_64-unknown-linux-gnu/llvm/bin/opt  -load ./LLVMIOSan.so -APIMODAnalysis -gvn -licm  -interface ./uniq_interface.data < $(APP_BITCODE) > /dev/null

run_enclave:
	/home/arslan/Documents/LBC/rustc/rust/rust_ws/../build/x86_64-unknown-linux-gnu/llvm/bin/opt  -load ./LLVMIOSan.so -APIMODAnalysis -gvn -licm  -interface ./uniq_interface.data < $(ENCLAVE_BITCODE) > /dev/null

run_enclave_dump:
	/home/arslan/Documents/LBC/rustc/rust/rust_ws/../build/x86_64-unknown-linux-gnu/llvm/bin/opt  -load ./LLVMIOSan.so -APIMODAnalysis -gvn -licm  -interface ./uniq_interface.data < $(ENCLAVE_BITCODE) > /dev/null 2>dump

run_dump:
	/home/arslan/Documents/LBC/rustc/rust/rust_ws/../build/x86_64-unknown-linux-gnu/llvm/bin/opt  -load ./LLVMIOSan.so -APIMODAnalysis -gvn -licm  -interface ./uniq_interface.data < $(APP_BITCODE) > /dev/null  2>dump
