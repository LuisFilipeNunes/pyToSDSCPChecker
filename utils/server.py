from tabulate import tabulate
import socket
import time
from scapy.layers.inet import IP, UDP, TCP
from scapy.all import *
from utils.commons import calculate_bit_operation,get_DSCP_code,DSCP_CODES

PORT = 12345

def udp_server(host, port, timeout):
    """
    UDP server function that listens for incoming messages.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((host, port))
        print(f"UDP server is listening on {host}:{port}")
        last_received_time = time.time()
        last_printed_timeout = False
        while True:
            server_socket.settimeout(1)
            try:
                data, addr = server_socket.recvfrom(1024)
                last_received_time = time.time()
                last_printed_timeout = False
            except socket.timeout:
                if time.time() - last_received_time > timeout and not last_printed_timeout:
                    print("=" * 6 + "#" * 46 + "=" * 6)
                    last_printed_timeout = True
                continue
                    
def start_udp_server(timeout):
    """
    Function to start the UDP server.
    """
    HOST = "0.0.0.0"
    
    udp_server(HOST, PORT, timeout)


def receive_packets(expected_tos):
    """
    Receives packets and displays packet information.
    
    Args:
        expected_tos (int): The expected Type of Service (tos) value to filter packets.
    
    """

    def packet_callback(packet,  expected_tos=expected_tos):
        """
        Callback function to handle each received packet.
        """
        # Check if the packet is UDP and on port 12345
        if UDP in packet and packet[UDP].dport == PORT:
            # Extract packet information
            payload = packet[Raw].load.decode() if Raw in packet else ""
            src_ip = packet[IP].src
            tos = packet[IP].tos
            if expected_tos == 65:
                expected_tos = calculate_bit_operation(tos, reverse=True)
            tos = calculate_bit_operation(tos, reverse=True)
            if tos == expected_tos:
                # Calculate transfer for this packet
                transfer = len(payload)            
                dscp_code = get_DSCP_code(tos)
                dscp_info = f"DSCP Code: {dscp_code} ({tos})"
                # Prepare data for tabular format
                table_data = [["Source IP", "DSCP Received", "Transfer Size"],
                              [src_ip, dscp_info, transfer]]

                # Print total transfer and throughput
                print(tabulate(table_data, headers="firstrow", tablefmt="fancy_grid"))
            else:
                table_data = [["Source IP", "Denial Reason", "DSCP - ToS"],
                              [src_ip, "Ignoring packet with unexpected DSCP value", tos]]

                print(tabulate(table_data, headers="firstrow", tablefmt="fancy_grid"))

    # Start sniffing packets on the network interface
    sniff(prn=packet_callback, filter="udp", store=0)
