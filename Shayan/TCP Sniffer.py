# Shayan Javid
# Dr. Bartlett
# TCP-SYN Sniffer
from scapy.all import *

cnt = 0
def packet_format(packet):
    global cnt
    cnt+=1
    return "packet #{}: {} --> {}".format(cnt, packet[0][1].src, packet[0][1].dst)
    
    
sniff (filter = "tcp[tcpflags] & 2 == 2 and tcp[tcpflags] & 16 == 0", prn=packet_format)
