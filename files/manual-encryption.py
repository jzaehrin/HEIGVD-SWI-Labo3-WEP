#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
import zlib
from rc4 import RC4

if len(sys.argv) == 3: # Demand number of fake SSID
    key = binascii.unhexlify(sys.argv[1].replace(":", ""))
    message = binascii.unhexlify(sys.argv[2].replace(":", ""))
else: # Reading file spliting every '\n'
    print("%s <key> <message>" % sys.argv[0])
    print("\tkey has [0-9A-F]{2}((:)?[0-9A-F]{2})*")
    print("\tmessage has [0-9A-F]{2}((:)?[0-9A-F]{2})*")
    exit(-1)

# Creation de la checksum du message
icv = struct.pack('<L', binascii.crc32(message))

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# Creation du streamcipher
cipher = RC4(seed, streaming=True)

# chiffre le message et le change dans la trame
arp.wepdata = cipher.crypt(message)

# chiffre l'ICV et le stock dans la trame en int
arp.icv = struct.unpack('!L', cipher.crypt(icv))[0]

# Ecriture du pcap
wrpcap('enc.pcap', arp)
