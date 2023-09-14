#!/bin/bash
echo '$0 = ' $0
echo '$1 = ' $1
echo '$2 = ' $2
cat $1 > $PWD/temp
make clean
make app
cp ./app $2/
cd $2/
afl-fuzz  -m 50000000 -i ./in/ -o ./out/ ./app
