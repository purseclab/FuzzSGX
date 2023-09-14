# Requires -ld -lpthread -lrt -ldl
#
include ../env.mk

all: libsgx_tsgxfuzz.a

libsgx_tsgxfuzz.o: libsgx_tsgxfuzz.c
	$(CC) -c $(C_FLAGS) $< -o $@ -I $(SGX_SDK)/include

libsgx_tsgxfuzz.a: libsgx_tsgxfuzz.o
	ar rcs $@ $<

clean:
	rm *.o *.a
