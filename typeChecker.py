#Luis Nunes

import argparse
import random
import string
import signal
import sys
import time
from scapy.layers.inet import IP, UDP, TCP
from scapy.all import *
from tabulate import tabulate

# Global variables to track transfer and throughput
start_time = time.time()
INTERVAL = 0.4 # Interval 40% of a second.
MAX_PAYLOAD_SIZE = 65535 # Maximum size allowed for TCP checksum calculation.


def calculate_bit_operation(tos, reverse = False):  
    transformations = {
        11: 40,  12: 48,  13: 56,
        21: 72,  22: 80,  23: 88,
        31: 104, 32: 112, 33: 120,
        41: 136, 42: 144, 43: 152,
        44: 44, 46:46
    }
    
    #go dict lookup go
    if reverse:
        for key, value in transformations.items():
            if value == tos:
                return key
        return tos/32
        
    if tos <= 7:
        return tos*32
        
    return transformations.get(tos, 0)
    
def packet_crafter(ip_address, tos, message_size_bytes=None):
    """
    Crafts an IPv4 packet with the specified tos value and payload.

    Args:
        ip_address (str): The destination IP address.
        tos (int): The Type of Service (tos) value.
        message_size_bytes (int): The size of the message payload in bytes.
    """
    if message_size_bytes:
        # Generate random data of the specified size
        payload = ''.join(random.choices(string.ascii_letters + string.digits, k=message_size_bytes))
    else:
        payload = "Hello, this is a test message"  # Default message
    packet = IP(dst=ip_address, tos=calculate_bit_operation(tos)) / UDP(sport=12345, dport=12345) / Raw(load=payload)
    send(packet, verbose=False)
    if message_size_bytes:
        print(len(payload.encode()))
    print("Packet Sent")
    # Wait for the specified interval before sending the next packet
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



def receive_packets(expected_tos):
    """
    Receives packets and displays packet information.
    
    Args:
        expected_tos (int): The expected Type of Service (tos) value to filter packets.
    
    """
    global start_time
    packets = sniff(filter="udp and port 12345", count=1)

    if packets:
        # Extract packet information
        packet = packets[0]
        payload = packet[Raw].load.decode() if packet.haslayer(Raw) else ""
        src_ip = packet[IP].src
        tos = packet[IP].tos
        if expected_tos == 65:
            expected_tos = calculate_bit_operation(tos, reverse = True)
        tos = calculate_bit_operation(tos, reverse = True)
        if tos == expected_tos:
            # Calculate transfer for this packet
            transfer = len(payload)

            # Calculate elapsed time since the last packet
            current_time = time.time()
            elapsed_time = current_time - start_time
            start_time = current_time
            elapsed_time = time.time() - start_time

            if elapsed_time > 0:
                # Calculate bitrate
                bitrate = transfer / elapsed_time  # Convert bytes to bits
                # Convert bitrate to KB/s or MB/s if necessary
                if bitrate >= 1e6:  # If bitrate >= 1 Megabyte/sec
                    bitrate = bitrate / 1e6
                    bitrate_unit = "MB/s"
                elif bitrate >= 1e3:  # If bitrate >= 1 Kilobyte/sec
                    bitrate = bitrate / 1e3
                    bitrate_unit = "KB/s"
                else:  # Otherwise, keep it in bytes/sec
                    bitrate_unit = "bytes/sec"
            else:
                bitrate = 0
                bitrate_unit = "bytes/sec"  # If elapsed_time is zero or negative

            # Prepare data for tabular format
            table_data = [["Source IP", "DSCP Received", "Transfer", f"Bitrate ({bitrate_unit})"],
                          [src_ip, tos, transfer, f"{bitrate:.2f}"]]

            # Print total transfer and throughput
            print(tabulate(table_data, headers="firstrow", tablefmt="fancy_grid"))
        else:
            table_data = [["Source IP", "Denial Reason", "DSCP - ToS"],
                          [src_ip, "Ignoring packet with unexpected DSCP - ToS value", tos]]

            print(tabulate(table_data,headers="firstrow", tablefmt="fancy_grid"))

    else:
        print("No packets received")

def main():
    """
    Main function to handle command-line arguments and execute packet sending or receiving.
    """
    parser = argparse.ArgumentParser(description="Send or receive packets with specified Type of Service (tos)")
    parser.add_argument("-c", "--client", metavar="IP_ADDRESS", help="Send packets with specified tos to the given IP address")
    parser.add_argument("-s", "--server",action="store_true", help="Expect packets with a specified tos")
    parser.add_argument("--tos", metavar="DSCP Code",type=int, default=None, help="Specify the DSCP code for the packets [0-56]")
    parser.add_argument("--inf", action="store_true", default=False, help="Send packets continuously until interrupted")
    parser.add_argument("--load", type=int, help="Specify the size of the packet payload in bytes")

    args = parser.parse_args()

    if args.client:
        if args.tos is None or args.tos > 56:
            parser.error("The --tos argument is required when using -c. It should be a number between 0 and 56")
        send_packets(args.client, args.tos, args.inf, args.load)
        
    elif args.server:
        # Set up signal handler for SIGINT (Ctrl+C) to exit the server
        signal.signal(signal.SIGINT, signal_handler)
        if args.tos is None:
            args.tos = 65 #Above the maximum values. Used as flag to signal to the receiver it should expect the same value that it receives, i.e, don't expect. 
        # Continuously listen for packets
        while True:
            receive_packets(args.tos)
    else:
        parser.print_help()

def signal_handler(sig, frame):
    """
    Signal handler to exit the server.
    """
    print("Server canceled. Exiting.")
    sys.exit(0)

if __name__ == "__main__":
    main()
