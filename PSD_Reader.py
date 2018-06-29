#!/usr/bin/python2.7
#
# Reads PSD Files from TexasInstruments SmartRF Packet Sniffer BLE
#
from __future__ import print_function
import struct

from scapy.layers.bluetooth4LE import BTLE, BTLE_PPI
from scapy.layers.ppi import PPI

class PSD_Stream(object):
    def __init__(self, file_path):
        # Open a file
        self.fo = open(file_path, "rb+")

    def read_next(self):
        #read next packet from file
        head = self.fo.read(15)
        if head == "":
            #EOF
            return None
        data = self.fo.read(256)
        ifo, no, ts, plen = struct.unpack("<BIQH", head)
        #plen, = struct.unpack("<H", head[13:])

        noidea = data[0]
        data = data[1:plen]
        rssi_dbm = 0
        channel = 0
        if ifo & 1:
            rssi_dbm = ord(data[-2]) - 94
            channel = ord(data[-1]) & 0x7F
            data = data[:-2]

        #print("#"+str(no)+" "+hex(ord(noidea)))

        p = PPI()/BTLE(data)
        p.PPIFieldHeaders = BTLE_PPI(btle_channel=channel, rssi_avg=rssi_dbm)
        p.time = ts/1000.0

        return p

    def close(self):
        # Close opend file
        self.fo.close()

    def __exit__(self):
        self.close()
    def __iter__(self):
        return self
    def __next__(self):
        pkt = self.read_next()
        if pkt == None:
            raise StopIteration
        return pkt
    def next(self):
        return self.__next__()

if __name__ == "__main__":
    from scapy.utils import wrpcap
    import sys

    if len(sys.argv) == 1:
        print("Convert PSD to pcap")
        print("Usage: "+sys.argv[0]+" file")
        sys.exit(1)

    s = PSD_Stream(sys.argv[1])
        
    pkgs = []
    while True:
        p = s.read_next()
        if p==None:
            break

#        p = BTLE(p.load)
#
#        print("CRC should be: "+hex(p[BTLE].crc))
#        del p[BTLE].crc
#        p.show2()
#        break

        pkgs.append(p)
    s.close()
    wrpcap(sys.argv[1]+'.pcap',pkgs)
