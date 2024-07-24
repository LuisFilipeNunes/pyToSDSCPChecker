import argparse
import signal
import sys
from scapy.layers.inet import IP, UDP, TCP
from scapy.all import *
from utils.client import *
from utils.server import *
from utils.commons import DSCP_CODES, DSCP_CODES_NUM


def main():
    """
    Main function to handle command-line arguments and execute packet sending or receiving.
    """
    parser = argparse.ArgumentParser(description="Send or receive packets with specified Type of Service (tos)")
    parser.add_argument("-c", "--client", metavar="IP_ADDRESS", help="Send packets with specified tos to the given IP address")
    parser.add_argument("-s", "--server",action="store_true", help="Expect packets with a specified tos")
    parser.add_argument("--dscp", metavar="DSCP_CODE", type=str, default=None, help="Specify the DSCP code (e.g., AF11, CS0, EF, VA)")
    parser.add_argument("--inf", action="store_true", default=False, help="Send packets continuously until interrupted")
    parser.add_argument("--load", type=int, help="Specify the size of the packet payload in bytes")
    parser.add_argument("--all", action="store_true", help="Send one packet for each DSCP value")
    parser.add_argument("--timeout", type=int, default=22, help="Set a timeout for the visual signal for the server.")

    args = parser.parse_args()
    args.dscp = args.dscp.upper() if args.dscp is not None else None

    if args.client:
        if args.all:
            for dscp_code in DSCP_CODES:
                dcsp_value = DSCP_CODES[dscp_code]
                send_packets(args.client, dcsp_value, False, args.load)
        else:
            
            if args.dscp is None:
                parser.error("The --dscp argument is required when using -c. It should be a DSCP code (e.g., AF11, CS0, EF, VA)")
            if args.dscp not in DSCP_CODES and args.dscp not in DSCP_CODES_NUM:
                parser.error(f"Invalid DSCP code: {args.dscp}. Please use a valid DSCP code (e.g., AF11, CS0, EF, VA or at least its numbers.)")
            try:
                dcsp_value = DSCP_CODES[args.dscp]
            except KeyError:
                try: 
                    dcsp_value = DSCP_CODES_NUM[args.dscp]
                except KeyError:
                    raise ValueError(f"Invalid DSCP value: {args.dscp}") 
            send_packets(args.client, dcsp_value, args.inf, args.load)
        
    elif args.server:
        udp_server_thread = threading.Thread(target=start_udp_server, args=(args.timeout,))
        udp_server_thread.daemon = True  # Set the thread as daemon
        udp_server_thread.start()
        
        # Set up signal handler for SIGINT (Ctrl+C) to exit the server
        signal.signal(signal.SIGINT, signal_handler)
        
        if args.dscp is None:
            args.dscp = 65 #Above the maximum values. Used as flag to signal to the receiver it should expect the same value that it receives, i.e, don't expect. 
        # Continuously listen for packets
        
        try:
            while True:
                receive_packets(args.dscp)
        except KeyboardInterrupt:
            print("\nServer canceled. Exiting.")
            sys.exit(0)
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
