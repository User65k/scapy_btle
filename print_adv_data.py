#!/usr/bin/python2.7
#
# parse BTLE communication
# use with: git clone https://github.com/User65k/scapy_btle.git
#
from __future__ import print_function
import sys

from scapy.layers.bluetooth4LE import BTLE_ADV_IND
from scapy.utils import PcapReader

from PSD_Reader import PSD_Stream

from binascii import hexlify

if __name__ == "__main__":

    if len(sys.argv) == 1:
        print("Usage: "+sys.argv[0]+" file")
        sys.exit(1)

    filename = sys.argv[1]
    if filename.endswith(".psd"):
        s = PSD_Stream(filename)
    else:
        s = PcapReader(filename)

    printed = []

    for p in s:
        
        #break
        #p = BTLE(p.load)

        if p.haslayer(BTLE_ADV_IND):
            adv = p[BTLE_ADV_IND]
            if not adv.AdvA in printed:
                adv.show()
                print("eir_data: %s\n"%(hexlify(str(adv)[6:])))
                
                printed.append(adv.AdvA)

