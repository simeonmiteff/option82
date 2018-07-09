DHCP option 82 is the "Relay Agent Information Option" that network equipment can insert into DHCP client requests to include pertinent information in the form of sub-options. This information may identify the agent itself, the port or interface facing the client, etc. An agent could be the DHCP relay itself (often the first hop router), or a capable aggregation device (like a switch) between the client and the network.

There are 13 or more documented sub-option types, of which Agent Circuit ID and Agent Remote ID are the most common and interesting. Cisco has a documented binary structure for the data payload of both types, and it seems Juniper uses text strings (with extra null termination for good luck).

The option82 program reads DHCPv4 packets via libpcap (network or file input) and outputs JSON strings to a log file, stdout, or syslog, containing fields that should aid network support, incident handling, or forensics. It uses a simple heuristic to detect binary sub-options and tries to decode them, falling back to outputting strings and hex encoded binary values as appropriate.

The tool is designed to work for offline analysis of PCAP files, as well as listening to live network traffic while running on a router, DHCP server or tap/mirror packet capture host.
