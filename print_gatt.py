#!/usr/bin/python2.7
#
# Print [G]ATT communication from pcap oder psd
#
from __future__ import print_function
import sys

from bt4LE import BTLE_ADV_IND, BTLE_DATA
from bt4LE_GATT import *
from scapy.layers.bluetooth import ATT_Read_Request, ATT_Read_Response, ATT_Write_Request

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
    
    for p in s:

#        if p.haslayer(BTLE_ADV_IND):
#            continue

        if p.haslayer(BTLE_DATA):
            b = p[BTLE_DATA]
            if b.LLID==1 and b.len > 0:
                #do something about fragments
                b.show()

        if p.haslayer(ATT_Read_Request):
            print("R: "+hex(p[ATT_Read_Request].gatt_handle))
        elif p.haslayer(ATT_Read_Response):
            print(">  "+hexlify(p[ATT_Read_Response].value))
        elif p.haslayer(ATT_Write_Request):
            print("W: "+hex(p[ATT_Write_Request].gatt_handle))
            print(">  "+hexlify(p[ATT_Write_Request].data))
        elif p.haslayer(PrepareWriteReq):
            h = p[PrepareWriteReq].Handle
            o = p[PrepareWriteReq].Offset
            v = hexlify(p[PrepareWriteReq].Value)
            print("W: "+hex(h))
            print("> "+str(o)+" > "+v)
        else:
            print(p.summary())
