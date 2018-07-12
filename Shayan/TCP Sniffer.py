# Shayan Javid
# Dr. Bartlett
# TCP-SYN Sniffer with Info
from scapy.all import *
import netifaces
import sqlite3
import os
import platform
import _datetime

#creating a database
sqlite_file = '~/Desktop/data.db'
conn = sqlite3.connect (sqlite_file)
c = conn.cursor()
#creating table
c.execute('CREATE TABLE GrayStar (packet_number INT, src_IP TEXT, src_port INT, dst_ip TEXT, dst_port INT, time TEXT, flag TEXT, len INT)')

if platform.system() == 'Darwin' or platform.system() == 'Linux':
    print("Hey you are in macOS/Linux")
    os.system('lsof -i | grep LISTEN')
elif platform.system() == 'Windows':
    os.system('netstat -apn tcp')    # cmd does not have grep
else:
    print("Not able to detect the system.")

netifaces.interfaces()

netifaces.ifaddresses('en0')        #en0 = WiFi         en1 = Thunderbolt1      en2 = Thunderbolt2

addrs = []

for interface in netifaces.interfaces():

    try:

        print(netifaces.ifaddresses(interface)[netifaces.AF_INET])

        for link in netifaces.ifaddresses(interface)[netifaces.AF_INET]:

            addrs.append(link['addr'])

    except Exception as e:

        pass


local_ip = addrs[1]

# Finding the device to sniff on
nf = netifaces.gateways()
dev = nf['default'][netifaces.AF_INET][1]

cnt = 0
def packet_format(packet):
    currentDT = datetime.now()
    global cnt
    if local_ip == packet[0][1].dst:
        cnt += 1
        flag = packet.sprintf("%TCP.flags%")
        if flag == 'R':
            flag = 'RST'
        elif flag == 'S':
            flag = 'SYN'
        else:
            flag = packet.sprintf("%TCP.flags%")
        length = len (packet)
        c.execute ("INSERT INTO GrayStar VALUES (?,?,?,?,?,?,?,?)", (cnt, packet[0][1].src,packet.sport, packet[0][1].dst, packet.dport, str(currentDT.hour) + str(currentDT.minute) +str(currentDT.second), flag, length))
        conn.commit()
        return "packet #{}: Source IP: {}     Source Port: {}     --> Destination IP: {}      Destination Port: {}" \
               "  *Time: {}:{}:{}   Flag: {} Length: {}"\
            .format(cnt, packet[0][1].src,packet.sport, packet[0][1].dst, packet.dport, currentDT.hour,currentDT.minute
                    ,currentDT.second, flag, length)


sniff (iface = dev,filter = "tcp[tcpflags] & (tcp-ack) == 0 and (tcp-syn) != 0", prn=packet_format)
conn.close()



