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
import math
from rc4 import RC4

if len(sys.argv) == 3: # Demand number of fake SSID
    key = binascii.unhexlify(sys.argv[1].replace(":", ""))
    message = binascii.unhexlify(sys.argv[2].replace(":", ""))
    n = len(message) // 35
else: # Reading file spliting every '\n'
    print("%s <key> <message>" % sys.argv[0])
    print("\tkey has [0-9A-F]{2}((:)?[0-9A-F]{2})*")
    print("\tmessage has [0-9A-F]{2}((:)?[0-9A-F]{2})*")
    exit(-1)

# Découpage du message en n fragment (Attention la fragmentation en bloc de moins de 32 bits ne fonctionne pas)
frag_len=36


fragments = [message[i * frag_len: min((i + 1) * frag_len, len(message))] for i in range(0, n)]

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
template = rdpcap('arp.cap')[0]

# Init la liste des packets
packets = []

# rc4 seed est composé de IV+clé
seed = template.iv+key

for i, fragment in enumerate(fragments):
    print(fragment)
    print(len(fragment))
    # Creation du streamcipher départ pour chaque fragment
    cipher = RC4(seed, streaming=True)

    # Copy du template et numérotation de celui-ci (Sequence number + Fragment number)
    packet = template.copy()
    packet.SC += i

    # Si ce n'est pas le dernier fragment, set le bit more-fragment
    if i != len(fragments) - 1:
        packet.FCfield |= 0x4
    else:
        fragment += b'\0' * (frag_len - len(fragment))
        packet.FCfield &= ~0x4
    # Creation de la checksum du message
    crc = struct.pack('<L', binascii.crc32(fragment))
    # chiffre le message et le change dans la trame
    cipher = cipher.crypt(fragment + crc)
    packet.wepdata = cipher[:-4]
    # chiffre l'ICV et le stock dans la trame en int
    packet.icv = struct.unpack('!L', cipher[-4:])[0]
    print("icv: %s" % binascii.crc32(fragment))

    # Ajout du fragment
    packets.append(packet)

# Ecriture du pcap
wrpcap('frag.pcap', packets)
