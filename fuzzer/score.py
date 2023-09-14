#!/usr/bin/python 

import sys, getopt
import os.path
from random import randrange,shuffle
import string
import random
from cStringIO import StringIO
from IPython import embed
mystdout = StringIO()
x={}
m={}
unfuzzSnippet=[]
fuzzSnippet=[]
#
typedefs = {}
stDef = 0
debugPrint = 0
parseBuf=[]
structs={}
aliases={}
isEnum = False
current = open("temp","w")
ec = {}
targetFuncs= []
import subprocess
bestScore = 0
baselineScore = 0
bestIndex = 0
import signal
import sys
import struct


def getScore():
    fname = "./out/fuzz_trace_best"
    numBlocks = 0
    numSet = 0
    blockHit = 0
    if(os.path.isfile(fname)):
        with open(fname) as f:
            for chunk in iter(lambda: f.read(4), b''):
                #print chunk
                if (len(chunk) != 4):
                    break
                num = struct.unpack('i', chunk)[0]
                for byte in range(3):
                    if (((num >> (byte * 8)) & 0xFF) == 0x80):
                        blockHit += 1
                numBlocks += 4


        if (blockHit == 0):
            with open(fname) as f:
                for chunk in iter(lambda: f.read(4), b''):
                    #print chunk
                    if (len(chunk) != 4):
                        break
                    num = struct.unpack('i', chunk)[0]
                    for byte in range(3):
                        if (((num >> (byte * 8)) & 0xFF) > 0):
                            blockHit += 1
                    numBlocks += 4
        return blockHit
    else:
        return 0

def main():
    score = getScore()
    print(score)
    

if __name__ == "__main__":
    main()
