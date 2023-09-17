import socket
from scapy.all import *
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.l2 import ARP


# def udp_scan(target, port):
#     udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     udp_socket.settimeout(2)
#     try:
#         udp_socket.sendto(b"DummyData", (target, port))
#         response, _ = udp_socket.recvfrom(1024)
#         print(f"Port {port} is open")
#     except socket.timeout:
#         print(f"Port {port} is closed")
#     except Exception as e:
#         print(f"Error: {e}")
#     finally:
#         udp_socket.close()

def udp_scan(target, port):
    try:
        # Create an IP packet with UDP layer
        ip_packet = IP(dst=target)
        udp_packet = UDP(dport=port)

        # Create a custom payload for the UDP packet (you can modify this payload)
        payload = b"DummyData"

        # Combine the IP, UDP, and payload layers
        udp_packet_with_payload = ip_packet / udp_packet / payload

        # Send the packet and receive a response
        response = sr1(udp_packet_with_payload, timeout=2, verbose=0)

        if response is None:
            print(f"Port {port} is filtered")
        else:
            print(f"Port {port} is open")
    except Exception as e:
        print(f"Error: {e}")


def ping_scan(host):
    resp = sr1(IP(dst=str(host)) / ICMP(), timeout=2, verbose=0)

    if resp is None:
        print(f"{host} is down or not responding.")
    elif (
            int(resp.getlayer(ICMP).type) == 3 and
            int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]
    ):
        print(f"{host} is blocking ICMP.")
    else:
        print(f"{host} is up.")


def arp_request(host):
    try:
        pkt = ARP(op=ARP.who_has, pdst=host)
        reply = sr1(pkt, timeout=1, verbose=0)
        print(" [-] Target MAC address: " + reply[ARP].hwsrc)
        return True
    except:
        return False


def icmp_request(host):
    pkt = IP(dst=host) / ICMP(seq=1)
    reply = sr1(pkt, timeout=1, verbose=0)
    if reply is not None:
        return True
    else:
        return False


def check_host_up(host):
    print(" [-] Checking if host (" + host + ") is up...")
    arp = arp_request(host)
    icmp = icmp_request(host)
    if arp or icmp:
        return True
    else:
        return False


# Exemple d'utilisation :
target_ip = "192.168.100.53"  # Remplacez par l'adresse IP de la cible
ports_to_scan = 161  # Liste des ports à scanner

# udp_scan(target_ip, ports_to_scan)
# ping_scan(target_ip)

if check_host_up(target_ip):
    udp_scan(target_ip, ports_to_scan)
else:
    print(" Host seems down. Is not replying the ping requests.\n")
