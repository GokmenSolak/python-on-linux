import scapy.all as scapy
from scapy.layers.http import HTTPRequest

def listen_packets(interface):
    scapy.sniff(iface = interface, store = False, prn =analyze_packets)

def analyze_packets(packet):
    #packet.show()
    if packet.haslayer(HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load.decode(errors = 'ignore'))

listen_packets("eth0")