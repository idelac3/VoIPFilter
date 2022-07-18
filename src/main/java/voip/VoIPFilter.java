package voip;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import packet.EthernetFrame;
import packet.Ip4Frame;
import packet.LinkLayerType;
import packet.LinuxCookedFrame;
import packet.PcapGlobalHeader;
import packet.PcapRecordHeader;
import pcap.PcapReader;

public class VoIPFilter {

	public static void main(String[] args) throws IOException {

		String filter = null, writeTo = null;
		
		final List<String> inputFiles = new ArrayList<>();
		
		//
		// Turn command argument array into List for easier manipulation. 
		//
		
		final List<String> argList = Arrays.asList(args).stream()
				.collect(Collectors.toList());
		
		if (argList.contains("-h") || argList.contains("--help")) {
			
			usage();
			
			return;
		}
		
		//
		// Process --filter and --write arguments. Also take last arguments as input PCAP files.
		//
		
		final Iterator<String> it = argList.iterator();
		while (it.hasNext()) {
		
			String val = it.next();
			
			if (val.equals("-f") || val.equals("--filter")) {
				
				if (it.hasNext() == false) {
					
					usage();
					
					System.err.println("Please set correct filter value.");
					
					return;
				}
				
				filter = it.next();
			}
			else if (val.equals("-w") || val.equals("--write")) {
				
				if (it.hasNext() == false) {
					
					usage();
					
					System.err.println("Please set correct output file where to write PCAP records.");
					
					return;
				}
				
				writeTo = it.next();
			}
			else {

				inputFiles.add(val);
			}
		}
		
		//
		// Extract input PCAP file names. They should appear as last arguments of this program.
		//
		
		final List<Path> files = inputFiles.stream()
				.map( (str) -> Paths.get(str) )
				.filter( (path) -> Files.isRegularFile(path) == true )
				.sorted( (path1, path2) -> {
					try {
						return Files.getLastModifiedTime(path1).compareTo(Files.getLastModifiedTime(path2));
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
					return 0;
				} )
				.collect(Collectors.toList());

		//
		// Warn if some PCAPs are not found.
		//
		
		final List<Path> nonExistingFiles = inputFiles.stream()
				.map( (str) -> Paths.get(str) )
				.filter( (path) -> Files.isRegularFile(path) == false )
				.collect(Collectors.toList());
		if (nonExistingFiles.size() > 0) {
			
			System.err.println("Unable to find following PCAP files: " + nonExistingFiles);
		}
		
		//
		// This handler is used to check if input PCAP record contains SIP messages that matches given filter value.
		//
		
		final SIPMatcherHandler handler = new SIPMatcherHandler(filter);
		
		//
		// Define output stream, usually file, or std.out if -w or --write argument is missing.
		//
		
		final OutputStream outputStream;
		if (writeTo == null) {
			
			outputStream = System.out;
		}
		else {
			
			outputStream = new FileOutputStream(new File(writeTo));
		}
		
		//
		// List of PCAP (file) input source(s). If none is specified, then std.in is used.
		// This is handy when tcpdump is invoked to redirect its output to std.out.
		//
		// Example:
		//	tcpdump -r myCapture.pcap -w - 'udp port 5060 or (ip[6:2] & 0x1fff != 0)' | java -jar VoIPFilter.jar -f 0912222333 | tcpdump -r - -w capture-0912222333.pcap
		// This example shows how to read myCapture.pcap file with tcpdump, 
		//  filter for UDP packets on port 5060 and include IP fragments,
		//  then write PCAP records to std.out.
		// VoIPFilter will then read from std.in PCAP records,
		//  filter for given phone number 0912222333 and 
		//  write only SIP packets that match given filter to std.out,
		// while last tcpdump will collect PCAP records and write to 'capture-0912222333.pcap' capture file.
		//
		
		final List<InputStream> inputStreams = new ArrayList<>();
		
		if (files.size() > 0) {
			
			for (final Path pcapFile : files) {

				inputStreams.add(new FileInputStream(pcapFile.toFile()));
			}
		}
		else {
			
			inputStreams.add(System.in);
		}
		
		final DataOutputStream out = new DataOutputStream(outputStream);
		
		byte[] globalHeader = null;
		
		for (final InputStream inputStream : inputStreams) {
			
			// Using Auto-Closeable feature of PCAP reader instance. Will auto close in try-with-resource block.
			try (
				final PcapReader reader = new PcapReader(new DataInputStream(inputStream)) ) {
				
				reader.setUdpHandler(handler);

				boolean running = true;
				while (running == true) {

					try {
					
						//
						// Here is a list containing PCAP records with IPv4 packets.
						// It's a list because IP packets might be fragmented.
						//
						// If IP packet is not fragmented then list contains only 1 PCAP record,
						//  otherwise it might contain more than one PCAP record.
						//
						
						final List<PcapRecordHeader> records = reader.readNext();

						if (globalHeader == null) {
							
							// When reading from multiple input PCAPs, use Linux 'cooked' link layer in output PCAP.
							globalHeader = PcapGlobalHeader.toByteArray(PcapGlobalHeader.MAGIC_SWAPPED
									, 0, 0, 0x400000, LinkLayerType.LINKTYPE_LINUX_SLL);
							
							// Write global header.  
							out.write(globalHeader);
						}
						
						//
						// Check if VoIP handler matched processed PCAP record(s).
						//
						
						if (handler.didMatch() == true) {

							for (final PcapRecordHeader record : records) {
							
								final boolean swapped = reader.getPcapGlobalHeader().isSwapped();
								final int linkLayerType = reader.getPcapGlobalHeader().getNetwork();
								
								// We can assume that this PCAP record contains IPv4 packet.								
								final Ip4Frame ip4frame = PcapReader.convertPcapRecordToIp4Frame(record, linkLayerType);
								final byte[] ipv4 = Ip4Frame.toByteArray(ip4frame);
								
								// Here we know that PCAP reader would only give back PCAP records with IPv4 packets.
								final byte[] linuxCookedHeader = LinuxCookedFrame.toByteArray(EthernetFrame.ETHERTYPE_IPv4);
								
								final int pcapRecordLen = linuxCookedHeader.length + ipv4.length;
								
								final byte[] pcapRecordHeader = PcapRecordHeader.toByteArray(swapped, record.getTs_sec(), record.getTs_usec()
										, pcapRecordLen, pcapRecordLen);
								
								//
								// Write in correct order: 
								//  1) PCAP record header
								//  2) Linux 'cooked' header
								//  3) IPv4 header with payload
								//
								
								out.write(pcapRecordHeader);								
								out.write(linuxCookedHeader);								
								out.write(ipv4);
							}
						}
					} catch (final EOFException eof) {
						
						running = false;
					}
				}
			}
			
			inputStream.close();
		}
		
		out.close();
	}
	
	public static void usage() {
		
		final String usage = String.format("VoIPFiler\n"
				+ "\n"
				+ "Usage: java -jar VoIPFilter.jar [args] [input PCAPs ...]\n"
				+ "Arguments:\n"
				+ " -f, --filter [value]     - will set filter string for filtering SIP sessions that match given value\n"
				+ " -w, --write [pcap file]  - set destination PCAP file where to write filtered packets\n"
				+ " [input PCAPs ...]        - set input PCAP files which will be used as source of packets\n"
				+ "\n"
				+ "NOTE: This program will work only with libpcap / tcpdump file formats (pcapng is not supported now).\n"
				+ "If input PCAP files are not specified, then std.input will be used as source.\n"
				+ "If output PCAP file is not set, then std.out will be used to write filtered packets.\n"
				+ "\n"
				+ "1) Example how to read with tcpdump and collect fragmented UDP packets:\n"				
				+ " tcpdump -r myCapture.pcap -w - 'udp port 5060 or (ip[6:2] & 0x1fff != 0)' | java -jar VoIPFilter.jar -f 0912222333 | tcpdump -r - -w capture-0912222333.pcap \n"
				+ "This example shows how to tell VoIPFilter to take input packets from tcpdump and write result ot std.out where another tcpdump will collect and write to destination PCAP file.\n"
				+ "\n"
				+ "2) Example how to merge several PCAP files into one PCAP file:\n"
				+ " java -jar VoIPFilter.jar -w merged.pcap myCapture-1.pcap myCapture-2.pcap my-Capture-3.pcap \n"
				+ "This example shows simple merging of input PCAPs, since no filter is set.\n"
				+ "\n"
				);
		
		System.out.println(usage);
	}
}
