#Basic packet sniffer with python by Burak "paradass" Görez

import scapy.all as scapy

class Sniffer:
    def get_packet(self,packet:scapy.Packet):
        if packet.haslayer(scapy.TCP):
            color = "\033[34m"
        elif packet.haslayer(scapy.UDP):
            color = "\033[33m"
        else:
            color = "\033[31m"
        print(f"{color}{packet.summary()}\033[0m")
    
    def listen(self):
        scapy.sniff(prn=self.get_packet)

sniffer = Sniffer()
sniffer.listen()