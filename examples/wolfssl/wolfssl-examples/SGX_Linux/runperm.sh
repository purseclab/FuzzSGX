#!/bin/bash
echo '$0 = ' $0
echo '$1 = ' $1
echo '$2 = ' $2
~/Documents/afl-head/AFL/afl-fuzz  -m 50000000 -i $2/in/ -o $2/out/ $2/App
