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

def packet_crafter(ip_address, cos, message_size_bytes=None):
    """
    Crafts an IPv4 packet with the specified CoS value and payload.

    Args:
        ip_address (str): The destination IP address.
        cos (int): The Class of Service (CoS) value.
        message_size_kb (int): The size of the message payload in kilobytes.
    """
    if message_size_bytes:
        # Generate random data of the specified size
        payload = ''.join(random.choices(string.ascii_letters + string.digits, k=message_size_bytes))
    else:
        payload = "Hello, this is a test message"  # Default message

    packet = IP(dst=ip_address, tos=cos << 3) / TCP(sport=12345, dport=12345) / Raw(load=payload)
    send(packet, verbose=False)

    transfer = len(payload.encode())
    print("Placeholder. just sent the packet.")
    print(f"Transfer: {transfer} bytes")

    # Wait for the specified interval before sending the next packet
    time.sleep(INTERVAL)

def send_packets(ip_address, cos, inf, message_size_bytes=None):
    """
    Sends packets with specified CoS to the given IP address.

    Args:
        ip_address (str): The destination IP address.
        cos (int): The Class of Service (CoS) value.
        inf (bool): Indicates whether to send packets continuously until interrupted.
        message_size_bytes (int): The size of the message payload in bytes.
    """
    try:
        if inf:
            while inf:
                packet_crafter(ip_address, cos, message_size_bytes)
        packet_crafter(ip_address, cos, message_size_bytes)
        
    except KeyboardInterrupt:
        print("\nSending interrupted by user. Exiting.")
        sys.exit(0)


def receive_packets(expected_cos):
    """
    Receives packets and displays packet information.
    
    Args:
        expected_cos (int): The expected Class of Service (CoS) value to filter packets.
    
    """
    global start_time
    packets = sniff(filter="tcp and port 12345", count=1)

    if packets:
        # Extract packet information
        packet = packets[0]
        payload = packet[Raw].load.decode() if packet.haslayer(Raw) else ""
        src_ip = packet[IP].src
        cos = packet[IP].tos >> 3
        if expected_cos == 114:
            expected_cos = cos
        
        if cos == expected_cos:
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
            table_data = [["Source IP", "CoS", "Transfer", f"Bitrate ({bitrate_unit})"],
                          [src_ip, cos, transfer, f"{bitrate:.2f}"]]

            # Print total transfer and throughput
            print(tabulate(table_data, headers="firstrow", tablefmt="fancy_grid"))
        else:
            table_data = [["Source IP", "Denial Reason", "CoS"],
                          [src_ip, "Ignoring packet with unexpected CoS value", cos]]

            print(tabulate(table_data,headers="firstrow", tablefmt="fancy_grid"))

    else:
        print("No packets received")

def main():
    """
    Main function to handle command-line arguments and execute packet sending or receiving.
    """
    parser = argparse.ArgumentParser(description="Send or receive packets with specified Class of Service (CoS)")
    parser.add_argument("-c", metavar="IP_ADDRESS", help="Send packets with specified CoS to the given IP address")
    parser.add_argument("-s", action="store_true", help="Expect packets with a specified CoS")
    parser.add_argument("--cos", type=int, default = None, help="Specify the Class of Service (CoS) for the packets")
    parser.add_argument("--inf", action="store_true", default=False, help="Send packets continuously until interrupted")
    parser.add_argument("--load", type=int, help="Specify the size of the packet payload in bytes")

    args = parser.parse_args()

    if args.c:
        if args.cos is None:
            parser.error("The --cos argument is required when using -c")
        send_packets(args.c, args.cos, args.inf, args.load)
        
    elif args.s:
        # Set up signal handler for SIGINT (Ctrl+C) to exit the server
        signal.signal(signal.SIGINT, signal_handler)
        if args.cos is None:
            args.cos = 114
        # Continuously listen for packets
        while True:
            receive_packets(args.cos)
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
