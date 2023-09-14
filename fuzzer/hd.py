import os.path
import sys
from IPython import embed
import struct

def getScore():
    fname = "./out/fuzz_trace_best"
    numBlocks = 0
    numSet = 0
    if(os.path.isfile(fname), "rb"):
        with open(fname) as f:
            for chunk in iter(lambda: f.read(4), b''):
                num = struct.unpack('i', chunk)[0]
                #print hex(num & 0xFF)
                for byte in range(3):
                    numSet += bin((num >> byte) & 0xFF).count("1")
                numBlocks += 4
            print ("Number of blocks:" + str(numBlocks))
            print ("Number of regions:" + str(numBlocks))
            print ("Number of regions fuzzed:" + str((numBlocks) - numSet))

    fname = "./out/fuzz_trace_best"
    numBlocks = 0
    numSet = 0
    blockHit = 0
    if(os.path.isfile(fname), "rb"):
        with open(fname) as f:
            for chunk in iter(lambda: f.read(4), b''):
                #print chunk
                if (len(chunk) != 4):
                    break
                num = struct.unpack('i', chunk)[0]
                for byte in range(3):
                    if (((num >> (byte * 8)) & 0xFF) > 0):
                        print ((num >> (byte * 8)) & 0xFF)
                        blockHit += 1
                numBlocks += 4

            print ("Blocks" + str(blockHit))


        if (blockHit == 0):
            with open(fname) as f:
                for chunk in iter(lambda: f.read(4), b''):
                    #print chunk
                    if (len(chunk) != 4):
                        break
                    num = struct.unpack('i', chunk)[0]
                    blockHit = blockHit + num
                    numBlocks += 4

        print ("Number of blocks:" + str(numBlocks))
        print ("Number of regions hit:" + str(blockHit))

            #print(line)
#          for chunk in iter(lambda: fp.read(32), b''):
#           print chunk.encode('hex')

def main(argv):
    getScore()

if __name__ == "__main__":
   if True:
       main(sys.argv)

