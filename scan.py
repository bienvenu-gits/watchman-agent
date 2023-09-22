import socket

# Define the range of IP addresses to scan (e.g., 192.168.1.1 to 192.168.1.254)
ip_range = "209.97.189.0-256"

# Define the port to check (SNMP typically uses port 161)
port = 161

# Function to check if a port is open on a given IP address
def is_port_open(ip, port):
    try:
        print(f"ip {ip}")
        # Create a socket object
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set a timeout for the connection attempt
            s.settimeout(1)
            # Try to connect to the IP address and port
            s.connect((ip, port))
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

# Split the IP range into the start and end IP addresses
start_ip, end_ip = ip_range.split('-')

# Convert the start and end IP addresses to integers
start_ip = int(start_ip.split('.')[-1])
end_ip = int(end_ip)

# Scan the IP addresses in the range for the open port
for i in range(start_ip, end_ip + 1):
    ip = f"209.97.189.{i}"  # Modify this according to your network configuration
    if is_port_open(ip, port):
        print(f"Port {port} is open on {ip}")