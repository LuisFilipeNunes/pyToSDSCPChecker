import random
import string
from scapy.layers.inet import IP, UDP, TCP
from scapy.all import *
from utils.commons import calculate_bit_operation, get_DSCP_code

INTERVAL = 0.4 # Interval 40% of a second.


def packet_crafter(ip_address, tos, message_size_bytes=None):
    """
    Crafts an IPv4 packet with the specified tos value and payload.

    Args:
        ip_address (str): The destination IP address.
        tos (int): The Type of Service (tos) value.
        message_size_bytes (int): The size of the message payload in bytes.
    """
    if message_size_bytes:
        payload = ''.join(random.choices(string.ascii_letters + string.digits, k=message_size_bytes))
    else:
        payload = "Hello, this is a test message"  # Default message
    packet = IP(dst=ip_address, tos=calculate_bit_operation(tos)) / UDP(sport=12345, dport=12345) / Raw(load=payload)
    send(packet, verbose=False)
    print(f"Packet Sent to {ip_address} with DSCP value of {tos}, code {get_DSCP_code(tos)} and a load of {len(payload.encode())} bytes")
    time.sleep(INTERVAL)

def send_packets(ip_address, tos, inf, message_size_bytes=None):
    """
    Sends packets with specified tos to the given IP address.

    Args:
        ip_address (str): The destination IP address.
        tos (int): The Type of Service (tos) value.
        inf (bool): Indicates whether to send packets continuously until interrupted.
        message_size_bytes (int): The size of the message payload in bytes.
    """
    try:
        if inf:
            while inf:
                packet_crafter(ip_address, tos, message_size_bytes)
        packet_crafter(ip_address, tos, message_size_bytes)
        
    except KeyboardInterrupt:
        print("\nSending interrupted by user. Exiting.")
        sys.exit(0)

