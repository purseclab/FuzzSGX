SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_WOLFSSL_LIB ?= ./
LIB_SFUZZ = $(CURDIR)/libFuzzSGX

ifndef WOLFSSL_ROOT
$(error WOLFSSL_ROOT is not set. Please set to root wolfssl directory)
endif


all:
	$(MAKE) -ef sgx_u.mk all
	$(MAKE) -ef sgx_t.mk all


update:
	cp ./template_kafl.cpp  ./untrusted/App.c

modeld:
	 $(MAKE) -ef sgx_u.mk modeld

clean:
	$(MAKE) -ef sgx_u.mk clean
	$(MAKE) -ef sgx_t.mk clean

