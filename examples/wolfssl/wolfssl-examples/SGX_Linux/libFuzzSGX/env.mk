DEBUG=0
CC=gcc
CXX=g++
ifeq ($(DEBUG), 1)
        C_FLAGS= -O0 -g -D DEBUG
else
        C_FLAGS= -O0 -g
endif
