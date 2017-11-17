## This file is for use with Scapy
## Bluetooth 4LE GAP layer

from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import *
from bt4LE import GAP_TYPES, BTLE_AdvData

class GAP_Flags(Packet):
    name = GAP_TYPES[1]
    fields_desc = [
        FlagsField("flags", 0, 8, [
            'LE Limited Discoverable Mode',
            'LE General Discoverable Mode',
            'BR/EDR Not Supported',
            'Simultaneous LE and BR/EDR (Controller)',
            'Simultaneous LE and BR/EDR (Host)'
        ])
    ]

class GAP_Power(Packet):
    name = GAP_TYPES[10]
    fields_desc = [
        SignedByteField("power [dbm]", 0)
    ]
class GAP_Name(Packet):
    name = GAP_TYPES[9]
    fields_desc = [
        StrField("name", "")
    ]

class GAP_UUIDList(Packet):
    name = GAP_TYPES[7]
    fields_desc = [
        PacketListField("uids", None, Raw, count_from=lambda pkt:pkt.len/16)
    ]
class GAP_service_data(Packet):
    name = GAP_TYPES[0x16]
    fields_desc = [
        ShortField("uuid", 0),
        StrField("data", "")
    ]
class GAP_manufacturer(GAP_service_data):
    name = GAP_TYPES[0xFF]
    #TODO beautify
    #manufacturer_uuids = {
    #    '004c': 'Apple, Inc.'
    #}
class GAP_slave_connection_interval_range(GAP_service_data):
    name = GAP_TYPES[0x12]
    #TODO beautify

bind_layers(BTLE_AdvData, GAP_Flags, type=1)
bind_layers(BTLE_AdvData, GAP_UUIDList, type=6)
bind_layers(BTLE_AdvData, GAP_UUIDList, type=7)
bind_layers(BTLE_AdvData, GAP_Name, type=9)
bind_layers(BTLE_AdvData, GAP_Power, type=10)
bind_layers(BTLE_AdvData, GAP_service_data, type=0x16)
bind_layers(BTLE_AdvData, GAP_manufacturer, type=0xFF)
bind_layers(BTLE_AdvData, GAP_slave_connection_interval_range, type=0x12)
