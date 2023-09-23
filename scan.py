import ipaddress
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

# if check_host_up(target_ip):
#     udp_scan(target_ip, ports_to_scan)
# else:
#     print(" Host seems down. Is not replying the ping requests.\n")


def is_valid_ip(ip):
    try:
        # Tentez de créer un objet IP à partir de la chaîne donnée
        ip = ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def is_ip_active(ip):
    try:
        # Exécutez la commande de ping
        result = subprocess.run(['ping', '-c', '1', '-w', '5', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)

        # Vérifiez le code de retour pour déterminer si le ping a réussi
        if result.returncode == 0:
            # Le ping a réussi, l'adresse IP est active
            return True
        else:
            if ip == "192.168.100.161":
                print(result)
            # Le ping a échoué, l'adresse IP est inactive
            return False
    except Exception as e:
        if ip == "192.168.100.161":
            print(e)
        # Une erreur s'est produite, l'adresse IP est probablement inactive
        return False


def snmp_scanner(ip, ports: list = None):
    if ports is None:
        ports = [161, 162]

    open_ports = []

    for port in ports:
        try:
            # Créez un objet socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Fixez un timeout court pour la connexion
            s.settimeout(1)

            # Tentez de se connecter à l'adresse IP et au port donnés
            s.connect((ip, port))
            # Si la connexion réussit, le port est ouvert
            print(f'IP : {ip}, Port: {port}, Status: open.')
            open_ports.append(port)
        except Exception as e:
            print(f'Connexion exception the host must probably filtering the port. Reason: {e}')
            print(f'IP : {ip}, Port: {port}, Status: closed.')
    return open_ports


def scan_snmp_and_append(ip, snmp_port, active_hosts):
    print(f"Scanning SNMP open host {ip}...")
    scan_result = snmp_scanner(ip=ip, ports=[snmp_port, 162])
    if len(scan_result) > 0:
        active_hosts.append(ip)


def scan_up_host_and_append(ip, active_hosts):
    print(f"Scanning open host {ip}...")
    active = is_ip_active(ip=ip)
    if active:
        active_hosts.append(ip)


def get_possible_active_hosts(ip_address, cidr):
    if not is_valid_ip(ip_address):
        raise ValueError("Invalid ip address")

    cidr_format = f'{ip_address}/{cidr}'
    # Utilisez la bibliothèque ipaddress pour analyser le CIDR
    network = ipaddress.IPv4Network(cidr_format, strict=False)

    # Obtenez la liste des adresses IP possibles dans le réseau
    hosts = []

    threads = []
    for ip in network.hosts():
        if ip in (network.network_address, network.broadcast_address):
            # Skip network and broadcast addresses
            continue

        host = str(ip)
        thread = threading.Thread(target=scan_up_host_and_append, args=(host, hosts))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return hosts


def get_snmp_hosts(network):
    print(f"target network {network}")
    active_hosts = []
    config = read_config()
    net_conf = config.get('network', {})
    cidr = net_conf.get('cidr', 24)
    ip = net_conf.get('ip', None)
    snmp_port = net_conf.get('snmp', {}).get('port', None)

    if not ip:
        raise ValueError("The network ip address must be provided.")

    if not snmp_port:
        raise ValueError("The configured snmp port must be provided.")

    hosts = get_possible_active_hosts(ip_address=ip, cidr=cidr)

    threads = []
    for host in hosts:
        thread = threading.Thread(target=scan_snmp_and_append, args=(host, snmp_port, active_hosts))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return active_hosts