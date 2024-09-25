# UDP Packet Receiver and Analyzer

This is a Python-based application for receiving, analyzing, and displaying UDP packets. The program allows you to monitor incoming UDP traffic, decode the Ethernet, IPv4, TCP, and UDP headers, and display detailed information about each packet. It also tracks and displays protocol statistics, including the percentage of total traffic for each protocol.

## Features

- **UDP Packet Receiver**: Listens for incoming UDP traffic on a specified IP and port.
- **Protocol Analysis**: Decodes and displays the Ethernet, IPv4, TCP, and UDP headers, including information such as source and destination IPs, ports, and protocol types.
- **HEX and ASCII Data View**: Provides a formatted view of packet data in both HEX and ASCII representations for easy analysis.
- **Known Ports Mapping**: Displays service names for known TCP and UDP ports such as HTTP, DNS, FTP, SIP, etc.
- **Protocol Statistics**: Tracks and displays the number and percentage of packets by protocol (Ethernet, IPv4, TCP, UDP).
- **Graphical User Interface**: Easy-to-use GUI built with `tkinter` for real-time packet display and statistics tracking.

## Requirements

- **Python 3.x**
- **tkinter**: Included with most Python installations.
- **struct**: Standard Python library.
- **socket**: Standard Python library.
## Example Output
```Ethernet II:
    Destination: 00:00:00_60:dd:19
    Source: Oracle_94:63:3e
    Type: 0x0800 (IPv4)

Internet Protocol Version 4:
    Source: 200.57.7.195
    Destination: 200.57.7.204
    Protocol: UDP

User Datagram Protocol:
    Source Port: 5060 (SIP)
    Destination Port: 5061 (SIP)
    Length: 706
    Checksum: 0x66d7

Hex Data and ASCII:
0000   00 00 00 60 dd 19 00 03 ba 94 63 3e 08 00 45 00   ...`......c>..E.
0010   02 d6 e0 0d 40 00 ff 11 f9 06 c8 39 07 c3 c8 39   ....@......9...9
0020   07 cc 13 c4 13 c5 02 c2 66 d7 49 4e 56 49 54 45   ........f.INVITE
```
## Customization
You can easily expand the list of known ports by adding additional entries to the known_ports dictionary in the source code.
Modify or extend the protocol analysis logic if you want to support other protocols beyond TCP and UDP.
## Contributing
If you would like to contribute to this project, please fork the repository and submit a pull request. Feel free to open issues for bug reports or feature requests.
