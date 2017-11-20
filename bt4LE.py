## This file is for use with Scapy
## Original: http://www.secdev.org/projects/scapy
## Bluetooth 4LE layer

import socket, struct

from scapy.config import conf
from scapy.data import MTU
from scapy.packet import *
from scapy.fields import *
from scapy.layers import dot11
from scapy.contrib.ppi import PPI, addPPIType, PPIGenericFldHdr
from scapy.contrib.ppi_geotag import XLEIntField, XLEShortField
from scapy.layers.bluetooth import EIR_Hdr

class HiddenField:
    '''
    Takes a field fld (like Emph does), and does not display it in pkt.show().
    If defaultonly==True, it will show the field in pkt.show() only if it differs from the defined default value.
    Useful for hidding reserved fields in packets, and generally decluttering output, without reducing functionality.
    '''
    fld = ""
    def __init__(self, fld, defaultonly=False):
        self.fld = fld
        self.defaultonly = defaultonly
    def to_show(self,pkt):
        if (self.defaultonly == True) and (pkt.getfieldval(self.fld.name) != self.fld.default):
            return True
        return False
    def __getattr__(self, attr):
        return getattr(self.fld,attr)
    def __hash__(self):
        return hash(self.fld)
    def __eq__(self, other):
        return self.fld == other

class BTLE_PPI(Packet):
    name = "BTLE PPI header"
    fields_desc = [
        HiddenField(LEShortField("pfh_type", 30006), defaultonly=True),
        HiddenField(LEShortField("pfh_datalen", 24)),
        ByteField("btle_version", 0),
        LEShortField("btle_channel", None),
        ByteField("btle_clkn_high", None),
        LEIntField("btle_clk_100ns", None),
        Field("rssi_max", None, fmt="b"),
        Field("rssi_min", None, fmt="b"),
        Field("rssi_avg", None, fmt="b"),
        ByteField("rssi_count", None)
    ]


class BDAddrField(MACField):
    def __init__(self, name, default, resolve=False):
        MACField.__init__(self, name, default)
        if resolve:
            conf.resolve.add(self)

    def i2m(self, pkt, x):
        if x is None:
            return "\0\0\0\0\0\0"
        return mac2str(':'.join(x.split(':')[::-1]))

    def m2i(self, pkt, x):
        return str2mac(x[::-1])


class BTLEChanMapField(XByteField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<Q")

    def addfield(self, pkt, s, val):
        return s+struct.pack(self.fmt, self.i2m(pkt, val))[:5]

    def getfield(self, pkt, s):
        return s[5:], self.m2i(pkt, struct.unpack(self.fmt, s[:5] + "\x00\x00\x00")[0])


class BTLE(Packet):
    name = "BT4LE"
    fields_desc = [
        XLEIntField("access_addr", 0x8E89BED6),
        X3BytesField("crc", None)
    ]

    @staticmethod
    def compute_crc(pdu, init=0x555555):
        def swapbits(a):
            v = 0
            if a & 0x80 != 0:
                v |= 0x01
            if a & 0x40 != 0:
                v |= 0x02
            if a & 0x20 != 0:
                v |= 0x04
            if a & 0x10 != 0:
                v |= 0x08
            if a & 0x08 != 0:
                v |= 0x10
            if a & 0x04 != 0:
                v |= 0x20
            if a & 0x02 != 0:
                v |= 0x40
            if a & 0x01 != 0:
                v |= 0x80
            return v

        state = swapbits(init & 0xff) + (swapbits((init >> 8) & 0xff) << 8) + (swapbits((init >> 16) & 0xff) << 16)
        lfsr_mask = 0x5a6000
        for i in (ord(x) for x in pdu):
            for j in xrange(8):
                next_bit = (state ^ i) & 1
                i >>= 1
                state >>= 1
                if next_bit:
                    state |= 1 << 23
                    state ^= lfsr_mask
        return struct.pack("<L", state)[:-1]

    def do_build(self):
        #make sure post build is called
        if not self.explicit:
            self=next(iter(self))
        pkt = self.self_build()
        for t in self.post_transforms:
            pkt = t(pkt)
        pay = self.do_build_payload()
        return self.post_build(pkt, pay)

    def post_build(self, p, pay):
        # Switch payload and CRC
        crc = p[-3:]
        p = p[:-3] + pay
        p += crc if self.crc is not None else self.compute_crc(p[4:])
        return p

    def pre_dissect(self, s):
        #move crc
        return s[:4] + s[-3:] + s[4:-3]

    def post_dissection(self, pkt):
        if isinstance(pkt, dot11.PPI):
            pkt.notdecoded = PPIGenericFldHdr(pkt.notdecoded)

    def hashret(self):
        return struct.pack("!L", self.access_addr)

#    def mysummary(self):
#        return hex(self.access_addr)


class BTLE_ADV(Packet):
    name = "BTLE advertising header"
    fields_desc = [
        BitEnumField("RxAdd", 0, 1, {0: "public", 1: "random"}),
        BitEnumField("TxAdd", 0, 1, {0: "public", 1: "random"}),
        HiddenField(BitField("RFU", 0, 2)),  # Unused
        BitEnumField("PDU_type", 0, 4, {0: "ADV_IND", 1: "ADV_DIRECT_IND", 2: "ADV_NONCONN_IND", 3: "SCAN_REQ",
                                        4: "SCAN_RSP", 5: "CONNECT_REQ", 6: "ADV_SCAN_IND"}),
        HiddenField(BitField("unused", 0, 2)),  # Unused
        XBitField("Length", None, 6),
    ]

    def post_build(self, p, pay):
        p += pay
        if self.Length is None:
            if len(pay) > 2:
                l = len(pay)
            else:
                l = 0
            p = p[0] + chr(l & 0x3f) + p[2:]
        if not isinstance(self.underlayer, BTLE):
            self.add_underlayer(BTLE)
        return p

    def mysummary(self):
        return "ADV type "+str(self.PDU_type)


class BTLE_DATA(Packet):
    name = "BTLE data header"
    fields_desc = [
        HiddenField(BitField("RFU", 0, 3)),  # Unused
        BitField("MoreData", 0, 1),
        BitField("SeqN", 0, 1),
        BitField("NESN", 0, 1),
        BitEnumField("LLID", 0, 2, {1: "continue", 2: "start", 3: "control"}),
        ByteField("len", 0)
    ]
    
    def mysummary(self):
        s = "Data"
        if isinstance(self.underlayer, BTLE):
            s += " "+hex(self.underlayer.crc)
        s += self.sprintf(" len: %BTLE_DATA.len% %BTLE_DATA.LLID%")
        if self.MoreData==1:
            s += " retry"
        return (s, [BTLE])

class BTLE_ADV_IND(Packet):
    name = "BTLE ADV_IND"
    fields_desc = [
        BDAddrField("AdvA", None),
        PacketListField("data", None, EIR_Hdr)
    ]
    def mysummary(self):
        adv_type_field = None
        if 0 < len(self.data):
            adv_type_field = EIR_Hdr().get_field('type')
        t = ", ".join(adv_type_field.i2repr(l, l.type) for l in self.data)
        return self.name+" "+self.AdvA+" > * / "+t


class BTLE_ADV_DIRECT_IND(Packet):
    name = "BTLE ADV_DIRECT_IND"
    fields_desc = [
        BDAddrField("AdvA", ""),
        BDAddrField("InitA", "")
    ]
    def mysummary(self):
        return "DIRECT_IND Adv: "+self.AdvA+" InitA: "+self.InitA


class BTLE_ADV_NONCONN_IND(BTLE_ADV_IND):
    name = "BTLE ADV_NONCONN_IND"


class BTLE_ADV_SCAN_IND(BTLE_ADV_IND):
    name = "BTLE ADV_SCAN_IND"


class BTLE_SCAN_REQ(Packet):
    name = "BTLE scan request"
    fields_desc = [
        BDAddrField("ScanA", ""),
        BDAddrField("AdvA", "")
    ]

    def answers(self, other):
        return BTLE_SCAN_RSP in other and self.AdvA == other.AdvA

    def mysummary(self):
        return "SCAN REQ "+self.ScanA+" > "+self.AdvA

class BTLE_SCAN_RSP(Packet):
    name = "BTLE scan response"
    fields_desc = [
        BDAddrField("AdvA", ""),
        PacketListField("data", None, EIR_Hdr)
    ]

    def answers(self, other):
        return BTLE_SCAN_REQ in other and self.AdvA == other.AdvA

    def mysummary(self):
        adv_type_field = None
        if 0 < len(self.data):
            adv_type_field = EIR_Hdr().get_field('type')
        t = ", ".join(adv_type_field.i2repr(l, l.type) for l in self.data)
        
        return self.sprintf("SCAN RESP %BTLE_SCAN_RSP.AdvA% > * / "+t)


class BTLE_CONNECT_REQ(Packet):
    name = "BTLE connect request"
    fields_desc = [
        BDAddrField("InitA", ""),
        BDAddrField("AdvA", ""),
        #LLDATA
        XIntField("AA", 0x00),
        X3BytesField("crc_init", 0x0),
        XByteField("win_size", 0x0),
        XLEShortField("win_offset", 0x0),
        XLEShortField("interval", 0x0),
        XLEShortField("latency", 0x0),
        XLEShortField("timeout", 0x0),
        BTLEChanMapField("chM", 0),
        BitField("SCA", 0, 3),
        BitField("hop", 0, 5),
    ]
    def mysummary(self):
        return "CON REQ "+self.InitA+" > "+self.AdvA+" Addr: "+hex(self.AA)+" hop "+str(self.hop)+" all "+str(self.interval*1.25)+"ms"+" chM "+hex(self.chM)


bind_layers(BTLE, BTLE_ADV, access_addr=0x8E89BED6)
bind_layers(BTLE, BTLE_DATA)
bind_layers(BTLE_ADV, BTLE_ADV_IND, PDU_type=0)
bind_layers(BTLE_ADV, BTLE_ADV_DIRECT_IND, PDU_type=1)
bind_layers(BTLE_ADV, BTLE_ADV_NONCONN_IND, PDU_type=2)
bind_layers(BTLE_ADV, BTLE_SCAN_REQ, PDU_type=3)
bind_layers(BTLE_ADV, BTLE_SCAN_RSP, PDU_type=4)
bind_layers(BTLE_ADV, BTLE_CONNECT_REQ, PDU_type=5)
bind_layers(BTLE_ADV, BTLE_ADV_SCAN_IND, PDU_type=6)

bind_layers(dot11.PPI, BTLE, dlt=147)
#bind_layers(PPI_FieldHeader, BTLE_PPI, pfh_type=30006)


bind_layers(PPI, BTLE, dlt=147)
addPPIType(30006, BTLE_PPI)
