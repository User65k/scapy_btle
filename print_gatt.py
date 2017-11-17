#!/usr/bin/python2.7
#
# Print [G]ATT communication from pcap oder psd
#
from __future__ import print_function
import sys

from bt4LE import BTLE_ADV_IND, BTLE_DATA
from bt4LE_GAP import *
from bt4LE_GATT import *
from scapy.layers.bluetooth import ATT_Hdr, ATT_Read_Request, ATT_Read_Response, ATT_Read_By_Group_Type_Request, ATT_Read_By_Group_Type_Response, ATT_Write_Request, ATT_Write_Response, ATT_Write_Command
#from scapy.packet import ls, Raw

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
            print("R: "+hex(p[ATT_Hdr].gatt_handle))
        if p.haslayer(ATT_Read_Response):
            print(">  "+hexlify(p[ATT_Hdr].value))
        if p.haslayer(ATT_Write_Request):
            print("W: "+hex(p[ATT_Hdr].gatt_handle))
            print(">  "+hexlify(p[ATT_Hdr].data))
        if p.haslayer(ATT_Write_Command):
            ls(p)
            break
        
    s.close()
