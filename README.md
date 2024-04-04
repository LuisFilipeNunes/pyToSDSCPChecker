# DCSP packet checker

This python script facilitates the sending and receiving of UDP packets with specified Type of Service (ToS) values. It can be utilized for testing network performances and examining packet transfer rates under different Quality of Service (QoS) configurations.

*   Features: Send Packets with custom ToS values (using DSCP values, ECN always 00) to a specified IP address.

*   Receive packets and display some packet information, as its load size, bitrate, and received DSCP value.

*   Support for specifying the size of the packet payload.

## Prerequisites

*   Python3.x installed on your system.

*   Requires Python libs:

    *   scapy : for crafting and analyzing packets.

    *   tabulate : for formatting packet information in a tabular format.

## Usage

1.  Sending Packets:

    *   Execute the script with the '-c' or "--client" flag followed by the destination IP address.

    *   use the "--tos" flag to specify thje DSCP code for the packets.(Required, should be a number between 0 and 56.)

    *   Optionally, use the "--inf" flag to send packets continuosly until interrupted.

    *   Optionally, spcefi the size of the packet load using the "--load" flag.
        Example: \$ python3 typeChecker.py -c 192.168.1.100 --tos 34 --inf --load 1024

2.  Receiving packets:

    *   Execute the script with the '-s' or "--server" flag.

    *   Optionally, use the "--tos" flag to specify the expected DSCP code for incoming packets. If not provided, the script will expect the same DSCP value as received.
        Example: \$ python3 typeChecker.py -s --tos 34

## DSCP Code Options

Below is a list of DSCP (Differentiated Services Code Point) codes along with their corresponding values and names:

| DSCP Value | DSCP Code   | Name                   |
| ---------- | ----------- | ---------------------- |
| 10         | AF11        | Assured Forwarding 11  |
| 12         | AF12        | Assured Forwarding 12  |
| 14         | AF13        | Assured Forwarding 13  |
| 18         | AF21        | Assured Forwarding 21  |
| 20         | AF22        | Assured Forwarding 22  |
| 22         | AF23        | Assured Forwarding 23  |
| 26         | AF31        | Assured Forwarding 31  |
| 28         | AF32        | Assured Forwarding 32  |
| 30         | AF33        | Assured Forwarding 33  |
| 34         | AF41        | Assured Forwarding 41  |
| 36         | AF42        | Assured Forwarding 42  |
| 38         | AF43        | Assured Forwarding 43  |
| 0          | CS0         | Class Selector/Default |
| 8          | CS1         | Class Selector 1       |
| 16         | CS2         | Class Selector 2       |
| 24         | CS3         | Class Selector 3       |
| 32         | CS4         | Class Selector 4       |
| 40         | CS5         | Class Selector 5       |
| 48         | CS6         | Class Selector 6       |
| 56         | CS7         | Class Selector 7       |
| 46         | EF          | Expedited Forwarding   |
| 44         | VOICE-ADMIT | Voice Admit            |

### Notes

*   The script uses UDP packets and listens on port 12345 for incoming packets.

*   Packet payload is "Hello, this is a test message", which is 29 bytes long, unless a specific size is provided, which then will be random generated data.

*   The script supports DSCP values ranging from 0 to 56. DSCP values outside this range will be ignored.

*   Transfer rate is calculated based on the time elapsed between received packets.

