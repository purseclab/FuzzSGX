#!/bin/bash
cat $1 > $PWD/temp
rm ./untrusted/App.c
rm ./App
rm ./untrusted/*.o
make
cp ./App $2/
cp ./untrusted/App.cpp $2/
cp ./Wolfssl_Enclave.signed.so $2/
