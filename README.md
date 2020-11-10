# VoIP Filter

Filtering network packets, extracting SIP sessions by tel. number or session ID value (Call-ID).

## Basic usage

Use command argument *-h* or **--help** to get usage information.



	VoIPFiler
	
	Usage: java -jar VoIPFilter.jar [args] [input PCAPs ...]
	Arguments:
	 -f, --filter [value]     - will set filter string for filtering SIP sessions that match given value
	 -w, --write [pcap file]  - set destination PCAP file where to write filtered packets
	 [input PCAPs ...]        - set input PCAP files which will be used as source of packets
	
	NOTE: This program will work only with libpcap / tcpdump file formats (pcapng is not supported now).
	If input PCAP files are not specified, then std.input will be used as source.
	If output PCAP file is not set, then std.out will be used to write filtered packets.
	
	1) Example how to read with tcpdump and collect fragmented UDP packets:
	 tcpdump -r myCapture.pcap -w - 'udp port 5060 or (ip[6:2] & 0x1fff != 0)' | java -jar VoIPFilter.jar -f 0912222333 | tcpdump -r - -w capture-0912222333.pcap 
	This example shows how to tell VoIPFilter to take input packets from tcpdump and write result ot std.out where another tcpdump will collect and write to destination PCAP file.
	
	2) Example how to merge several PCAP files into one PCAP file:
	 java -jar VoIPFilter.jar -w merged.pcap myCapture-1.pcap myCapture-2.pcap my-Capture-3.pcap 
	This example shows simple merging of input PCAPs, since no filter is set.

First specify parameters like **--filter** and **--write**, then input PCAP files.
If input PCAP files are not specified, then program will assumen std.in as input which is handy if **tcpdump** program will provide data.
If output PCAP file is not specified, then std.out will be used as destination. It allows programs like **tcpdump** to further accept and filter input packets.

### Filtering from PCAP file

Use **-f** argument with filter value, and specify input PCAP files.

Example:

`java -jar VoIPFilter.jar -f 1234 -w only1234.pcap myCapture.pcap`

will read input PCAP file **myCapture.pcap** and filter only SIP packets containing value **1234** in **From**, **To** or **Call-ID** headers.
Saved result is in **only-1234.pcap** file.
 
### Filtering from live packet stream

Use **-f** argument with filter value, and read input from **tcpdump** program.

Example:

`tcpdump -i eth0 -w - | java -jar VoIPFilter.jar -f 1234 -w only1234.pcap`

will read packets provided by **tcpdump** and filter only SIP packets containing value **1234** in **From**, **To** or **Call-ID** headers.
Saved result is in **only-1234.pcap** file.
 
## Supported formats

Wireshark/tcpdump [libpcap](https://wiki.wireshark.org/Development/LibpcapFileFormat) format is supported as input to VoIPFilter program.

Other formats like PcapNG are not supported.

## About

Author: igor.delac@gmail.com
