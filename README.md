# scapy_btle
Bluetooth Low Energy for scapy

## PSD_Reader.py
Use captures from TIs BTLE sniffer in scapy

```python
for pkt in PSD_Stream(filename):
    pkt.summary()
```

## print_gatt.py
Usage Example. Extranct GATT Layer and prints R/W stuff