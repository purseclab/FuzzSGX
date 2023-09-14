# Requires -ld -lpthread -lrt -ldl
#
include ../env.mk
all: libsgx_usgxfuzz.a

libsgx_usgxfuzz.o: libsgx_usgxfuzz.c
	$(CC) -c $(C_FLAGS) $< -o $@

libsgx_usgxfuzz.a: libsgx_usgxfuzz.o
	ar rcs $@ $<

clean:
	rm *.o *.a
