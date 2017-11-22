# scapy_btle
Bluetooth Low Energy for scapy

```
>>> read_resp.show()
###[ PPI Packet Header ]### 
  pph_version= 0
  pph_flags = 0
  pph_len   = None
  dlt       = 147
  \PPIFieldHeaders\
   |###[ BTLE PPI header ]### 
   |  pfh_type  = 30006
   |  pfh_datalen= 24
   |  btle_version= 0
   |  btle_channel= 31
   |  btle_clkn_high= None
   |  btle_clk_100ns= None
   |  rssi_max  = None
   |  rssi_min  = None
   |  rssi_avg  = -31
   |  rssi_count= None
###[ BT4LE ]### 
     access_addr= 0x889a7c54
     crc       = 0x60df9
###[ BTLE data header ]### 
        RFU       = 0L
        MoreData  = 0L
        SeqN      = 1L
        NESN      = 0L
        LLID      = start
        len       = 17
###[ L2CAP header ]### 
           len       = 13
           cid       = attribute
###[ ATT header ]### 
              opcode    = 0xb
###[ Read Response ]### 
                 value     = '\x0b\x05\x00\x00\xa1J.\xa1l\xd5\xd3>'

>>> adv_cn.show()
###[ PPI Packet Header ]### 
  pph_version= 0
  pph_flags = 0
  pph_len   = None
  dlt       = 147
  \PPIFieldHeaders\
   |###[ BTLE PPI header ]### 
   |  pfh_type  = 30006
   |  pfh_datalen= 24
   |  btle_version= 0
   |  btle_channel= 39
   |  btle_clkn_high= None
   |  btle_clk_100ns= None
   |  rssi_max  = None
   |  rssi_min  = None
   |  rssi_avg  = -85
   |  rssi_count= None
###[ BT4LE ]### 
     access_addr= 0x8e89bed6
     crc       = 0x4d15c2
###[ BTLE advertising header ]### 
        RxAdd     = public
        TxAdd     = random
        RFU       = 0L
        PDU_type  = ADV_NONCONN_IND
        unused    = 0L
        Length    = 0x1cL
###[ BTLE ADV_NONCONN_IND ]### 
           AdvA      = 1c:58:5e:25:b8:fe
           \data      \
            |###[ EIR Header ]### 
            |  len       = 14
            |  type      = mfg_specific_data
            |###[ EIR Manufacturer Specific Data ]### 
            |     company_id= 0xe3c6
            |     data      = '\x01) \x00\xf8+\xd6Lby\x80'
            |###[ EIR Header ]### 
            |  len       = 121
            |  type      = 92
            |###[ EIR Raw ]### 
            |     data      = '%\xb3\xb7\x94\xb1'
```

## PSD_Reader.py
Use captures from TIs BTLE sniffer (SmartRF Protocol Packet Sniffer) in scapy

```python
for pkt in PSD_Stream(filename):
    pkt.summary()
```

## print_gatt.py
Usage Example. Extranct GATT Layer and prints R/W stuff
