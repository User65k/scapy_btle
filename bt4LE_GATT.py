## This file is for use with Scapy
## Bluetooth 4LE GATT layer

from scapy.layers.bluetooth import L2CAP_Hdr, ATT_Hdr

from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import *
from bt4LE import BTLE_DATA

BTLE_Versions = {
    7: '4.1'
}
BTLE_Corp_IDs = {
    0xf: 'Broadcom Corporation'
}

class CtrlPDU(Packet):
    name = "CtrlPDU"
    fields_desc = [
        XByteField("optcode", 0),
        ByteEnumField("version", 0, BTLE_Versions),
        LEShortEnumField("Company", 0, BTLE_Corp_IDs),
        XShortField("Subversion", 0)
    ]

#BTLE_DATA / L2CAP_Hdr / ATT_Hdr
bind_layers(BTLE_DATA, L2CAP_Hdr, LLID=2)
# LLID=1 -> Continue
bind_layers(BTLE_DATA, CtrlPDU, LLID=3)


#stuff below should vanish at some point
class PrepareWriteReq(Packet):
    fields_desc = [
        XShortField("Handle", 0),
        ShortField("Offset", 0),
        StrField("Value", "")
    ]
class PrepareWriteResp(PrepareWriteReq):
    pass

class ExecWriteReq(Packet):
    fields_desc = [
        ByteField("Flags", 0)
    ]
class ExecWriteResp(Packet):
    pass

class ReadBlobReq(Packet):
    fields_desc = [
        XShortField("Handle", 0),
        ShortField("Offset", 0)
    ]

class ReadBlobResp(Packet):
    fields_desc = [
        StrField("Value", "")
    ]

bind_layers( ATT_Hdr, PrepareWriteReq, opcode=0x16)
bind_layers( ATT_Hdr, PrepareWriteResp, opcode=0x17)
bind_layers( ATT_Hdr, ExecWriteReq, opcode=0x18)
bind_layers( ATT_Hdr, ExecWriteResp, opcode=0x19)
bind_layers( ATT_Hdr, ReadBlobReq, opcode=0xc)
bind_layers( ATT_Hdr, ReadBlobResp, opcode=0xd)