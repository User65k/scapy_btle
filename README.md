# scapy_btle
Bluetooth Low Energy Tools using Scapy

## PSD_Reader.py
Use captures from TIs BTLE sniffer (SmartRF Protocol Packet Sniffer) in scapy

```python
for pkt in PSD_Stream(filename):
    pkt.summary()
```

## print_gatt.py
Extract GATT Layer and prints R/W stuff

```
$ python print_gatt.py ./handy2.psd 
PPI / BTLE / BTLE_ADV / BTLE_SCAN_REQ
PPI / BTLE / BTLE_ADV / BTLE_SCAN_RSP
PPI / BTLE / BTLE_ADV / BTLE_CONNECT_REQ
PPI / BTLE / BTLE_DATA / CtrlPDU
PPI / BTLE / BTLE_DATA / CtrlPDU
Read_By_Group_Type_Request range: 0x1 0xffff uuid: 0x2800
Read_By_Group_Type_Response data: '\x01\x00\x04\x00\x00\x18\x06\x00\x10\x00\x80\xff\x11\x00\xff\x00\n\x08'
Read_By_Type_Request range: 0xd 0x10 uuid: 0x2803
Read_By_Type_Response data: '\x07\xff\x00:\x0f\x00\xff\x02'
Find_Information_Request range: 0x10 0x10
Find_Information_Response data: '\x10\x00\xff)' 0x1
  W 0010: '\xff\x00'
  R 000f:
  R     : '\x00'
HVN 000f: '\x00'
 LW 0008: 0 '\x00\xff\xff\x00\xff\r\x13\xd2R5\xee_L\xce\xe8\xae\tO'
 LW 0008: 18 '\x90x\xd7\x9803\xfa9=A\xff\xf9\xd9\xc6\xb4\xa54'
HVN 000c: '\x12\x00\xec\xff\x8bu\xff\n\xbb`  O\xcf\xac=`\x19\xd0\x00'
```

## print_adv_data.py
Print Advertising Data for each MAC

```
$ python print_adv_data.py ./to_much_pkgs.psd 
###[ BTLE ADV_IND ]### 
  AdvA      = 00:1a:22:09:8d:1f
  \data      \
   |###[ EIR Header ]### 
   |  len       = 2
   |  type      = flags
   |###[ Flags ]### 
   |     flags     = limited_disc_mode+br_edr_not_supported
   |###[ EIR Header ]### 
   |  len       = 17
   |  type      = complete_list_128_bit_svc_uuids
   |###[ EIR Raw ]### 
   |     data      = '\x1b\xc5\xd5\xa5\x02\x007\xb7\xe6\x11\xd8\x15\x00i\xe0X'
   |###[ EIR Header ]### 
   |  len       = 8
   |  type      = complete_local_name
   |###[ Complete Local Name ]### 
   |     local_name= 'KEY-BLE'

eir_data: 02010511071bc5d5a5020037b7e611d8150069e05808094b45592d424c45

###[ BTLE ADV_IND ]### 
  AdvA      = 54:13:79:2c:c5:5a
  \data      \
   |###[ EIR Header ]### 
   |  len       = 2
   |  type      = flags
   |###[ Flags ]### 
   |     flags     = general_disc_mode+simul_le_br_edr_ctrl+simul_le_br_edr_host
   |###[ EIR Header ]### 
   |  len       = 17
   |  type      = complete_list_128_bit_svc_uuids
   |###[ EIR Raw ]### 
   |     data      = '\xfc]\xd0\xb3\xca\x84\xe0\x84\x06B\xf3\xf7\xe1\xe0\xbb\xcb'

eir_data: 02011a1107fc5dd0b3ca84e0840642f3f7e1e0bbcb
```
