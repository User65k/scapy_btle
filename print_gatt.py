#!/usr/bin/python2.7
#
# Print [G]ATT communication from pcap oder psd
#
from __future__ import print_function
import sys

from scapy.layers.bluetooth4LE import BTLE_ADV_IND, BTLE_DATA
from scapy.layers.bluetooth import ATT_Read_Request, ATT_Read_Response, ATT_Write_Request, ATT_Handle_Value_Notification, ATT_PrepareWriteReq, ATT_Hdr
from scapy.layers.bluetooth import ATT_Find_Information_Request, ATT_Find_Information_Response, ATT_Read_By_Type_Request, ATT_Read_By_Type_Response, ATT_Read_By_Group_Type_Request, ATT_Read_By_Group_Type_Response

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

        if p.haslayer(BTLE_ADV_IND):
            continue

        if p.haslayer(BTLE_DATA):
            b = p[BTLE_DATA]
            if b.LLID==1 and b.len > 0:
                #do something about fragments - or maybe not, as there seem to be none
                b.show()

        if p.haslayer(ATT_Read_Request):
            print('  R {p.gatt_handle:04x}:'.format(p=p[ATT_Read_Request]))
        elif p.haslayer(ATT_Read_Response):
            print('  R     : {p.value!r}'.format(p=p[ATT_Read_Response]))
        elif p.haslayer(ATT_Write_Request):
            print('  W {p.gatt_handle:04x}: {p.data!r}'.format(p=p[ATT_Write_Request]))
        elif p.haslayer(ATT_PrepareWriteReq):
            print(' LW {p.handle:04x}: {p.offset:d} {p.value!r}'.format(p=p[ATT_PrepareWriteReq]))
        elif p.haslayer(ATT_Handle_Value_Notification):
            print('HVN {p.handle:04x}: {p.value!r}'.format(p=p[ATT_Handle_Value_Notification]))

        #connection setup stuff
        elif p.haslayer(ATT_Find_Information_Request):
            print(p.sprintf("Find_Information_Request range: %ATT_Find_Information_Request.start% %ATT_Find_Information_Request.end%") )
        elif p.haslayer(ATT_Find_Information_Response):
            print(p.sprintf("Find_Information_Response data: %ATT_Find_Information_Response.data% %ATT_Find_Information_Response.format%") )
        elif p.haslayer(ATT_Read_By_Type_Request):
            print(p.sprintf("Read_By_Type_Request range: %ATT_Read_By_Type_Request.start% %ATT_Read_By_Type_Request.end% uuid: %ATT_Read_By_Type_Request.uuid%") )
        elif p.haslayer(ATT_Read_By_Type_Response):
            print(p.sprintf("Read_By_Type_Response data: %ATT_Read_By_Type_Response.data%") )
        elif p.haslayer(ATT_Read_By_Group_Type_Request):
            print(p.sprintf("Read_By_Group_Type_Request range: %ATT_Read_By_Group_Type_Request.start% %ATT_Read_By_Group_Type_Request.end% uuid: %ATT_Read_By_Group_Type_Request.uuid%") )
        elif p.haslayer(ATT_Read_By_Group_Type_Response):
            print(p.sprintf("Read_By_Group_Type_Response data: %ATT_Read_By_Group_Type_Response.data%") )
        
        elif p.haslayer(ATT_Hdr):
            pass
            #ACKs and stuff
        else:
            if p.haslayer(BTLE_DATA):
                if b.LLID==1 and b.len == 0:
                    continue #spam - idnk

            print(p.summary())
