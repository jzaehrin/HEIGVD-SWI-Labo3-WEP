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
from rc4 import RC4

if len(sys.argv) == 4: # Demand number of fake SSID
    key = binascii.unhexlify(sys.argv[1].replace(":", ""))
    n = int(sys.argv[2])
    message = binascii.unhexlify(sys.argv[3].replace(":", ""))
else: # Reading file spliting every '\n'
    print("%s <key> <nb frag> <message>" % sys.argv[0])
    print("\tkey has [0-9A-F]{2}((:)?[0-9A-F]{2})*")
    print("\tmessage has [0-9A-F]{2}((:)?[0-9A-F]{2})*")
    exit(-1)

# Découpage du message en n fragment (Attention la fragmentation en bloc de moins de 32 bits ne fonctionne pas)
fragments = [message[i:i+len(message)//n + 1] for i in range(0, len(message), len(message)//n + 1)]

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
template = rdpcap('arp.cap')[0]

# Init la liste des packets
packets = []

# rc4 seed est composé de IV+clé
seed = template.iv+key

for i, fragment in enumerate(fragments):
    # Creation du streamcipher départ pour chaque fragment
    cipher = RC4(seed, streaming=True)

    # Copy du template et numérotation de celui-ci (Sequence number + Fragment number)
    packet = template.copy()
    packet.SC += i

    # Si ce n'est pas le dernier fragment, set le bit more-fragment
    if i != (n-1):
        packet.FCfield |= 0x4

    # Creation de la checksum du message
    icv = struct.pack('<L', binascii.crc32(fragment))
    # chiffre le message et le change dans la trame
    packet.wepdata = cipher.crypt(fragment)
    # chiffre l'ICV et le stock dans la trame en int
    packet.icv = struct.unpack('!L', cipher.crypt(icv))[0]

    # Ajout du fragment
    packets.append(packet)

# Ecriture du pcap
wrpcap('frag.pcap', packets)
