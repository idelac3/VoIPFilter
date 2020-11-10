package pcap;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import packet.EthernetFrame;
import packet.Ip4Frame;
import packet.LinkLayerType;
import packet.LinuxCookedFrame;
import packet.PcapGlobalHeader;
import packet.PcapRecordHeader;
import packet.TcpPacket;
import packet.UdpDatagram;

/**
 * PCAP reader will collect IP packets from PCAP (file) source,
 *  do de-fragmentation of IPv4 payload, and
 *  invoke handlers for UDP and/or TCP.
 * <p>
 * See {@link #setTcpHandler(Consumer)} and {@link #setUdpHandler(Consumer)}
 * methods, on how to set appropriate handlers.
 *   
 */
public class PcapReader implements AutoCloseable {

	private final DataInputStream in;

	private Consumer<Ip4Frame> ipHandler;
	private Consumer<TcpPacket> tcpHandler;
	private Consumer<UdpDatagram> udpHandler;

	private PcapGlobalHeader globalHeader;
	
	/**
	 * Keep here PCAP records that contain fragments of one bigger IPv4 packet.
	 */
	private final List<PcapRecordHeader> fragmentsList;
	
	/**
	 * Prepare {@link PcapReader} to read captured packets
	 * from {@link InputStream}.
	 * 
	 * @param in	-	source of data, eg. {@link DataInputStream}
	 */
	public PcapReader(final DataInputStream in) {
	
		this.in = in;
		this.fragmentsList = new ArrayList<>();
	}
	
	/**
	 * Read single packet or PCAP record.
	 * <p>
	 * Method will try to return a list of {@link PcapRecordHeader} objects which carry single
	 * TCP or UDP message. This will provide defragmentation on IPv4 level. 
	 * 
	 * @return {@link PcapRecordHeader} objects, or empty list if {@link EOFException} occurs
	 * 
	 * @throws IOException	if I/O problem occurs while reading input data
	 */
	public List<PcapRecordHeader> readNext() throws IOException {
		
		final List<PcapRecordHeader> resultRecords = new ArrayList<>();
		
		if (this.globalHeader == null) {
			
			this.globalHeader = new PcapGlobalHeader(this.in);			
		}
		
		boolean swapped = this.globalHeader.isSwapped();
		
		final int linkLayerType = globalHeader.getNetwork();
		
		final PcapRecordHeader record = new PcapRecordHeader(in, swapped);		
		
		final byte[] payload;
		final int protocol;
		
		if (linkLayerType == LinkLayerType.LINKTYPE_ETHERNET) {
			
			final EthernetFrame ethernet = new EthernetFrame(record.getPayload());
			payload = ethernet.getPayload();
			
		
			protocol = ethernet.getEthertype();
		}
		else if (linkLayerType == LinkLayerType.LINKTYPE_LINUX_SLL) {
			
			final LinuxCookedFrame cooked = new LinuxCookedFrame(record.getPayload());
			payload = cooked.getPayload();
			
			protocol = cooked.getProto();
		}
		else {
			
			throw new IOException("Only Ethernet frames or Linux 'cooked' packets are supported.");			
		}
		
		//
		// Process only IPv4 packets.
		//
		
		if (protocol == EthernetFrame.ETHERTYPE_IPv4) {
			
			final Ip4Frame ip = new Ip4Frame(payload);
			
			if (this.ipHandler != null) {
				
				this.ipHandler.accept(ip);
			}

			// Collect fragments here.
			if (ip.getFragmentFlag() == 1 || ip.getFragmentOffset() > 0) {

				this.fragmentsList.add(record);
				
				//
				// Select only IP packets that belong to this fragment group.
				//
				
				final int fragmentGroup = ip.getFragmentGroupID();

				//
				// Here grouping is done, and also sorting, to fix scenarios in which 
				//  packets arrive out of order.
				//
				
				final List<Ip4Frame> groupPackets = this.fragmentsList.stream()
						.map( (pcapRecord) -> convertPcapRecordToIp4Frame(pcapRecord, linkLayerType) )
						.filter( (ip4frame) -> ip4frame.getFragmentGroupID() == fragmentGroup)
						.sorted( (ip1, ip2) -> Integer.compare(ip1.getFragmentOffset(), ip2.getFragmentOffset()) )
						.collect(Collectors.toList());
		
				int size = groupPackets.size();
				
				final Ip4Frame lastPacket = groupPackets.get(size - 1);
				
				// Last fragment arrived. At this point it should be fine to start assembly.
				if (lastPacket.getFragmentFlag() == 0 && size > 1) {
					
					int totalPayloadSize = 0;

					for (final Ip4Frame ip4frame : groupPackets ) {

						totalPayloadSize += ip4frame.getPayloadLen();
					}

					final byte[] defragPacketPayload = new byte[totalPayloadSize];

					int offset = 0;

					for (final Ip4Frame ip4frame : groupPackets ) {

						int length = ip4frame.getPayloadLen();

						ip4frame.getPayloadByteBuffer().get(defragPacketPayload, offset, length);

						offset += length;
					}

					if (this.tcpHandler != null && ip.getProtocol() == Ip4Frame.PROTO_TCP) {
						
						final TcpPacket tcp = new TcpPacket(defragPacketPayload);
						
						this.tcpHandler.accept(tcp);
					}
					
					if (this.udpHandler != null && ip.getProtocol() == Ip4Frame.PROTO_UDP) {
						
						final UdpDatagram udp = new UdpDatagram(defragPacketPayload);
						
						this.udpHandler.accept(udp);
					}
					
					//
					// Prepare final result.
					//
					
					final List<PcapRecordHeader> groupedRecords =
							this.fragmentsList.stream().filter( (pcapRecord) -> {
								
								final Ip4Frame ipPacket = convertPcapRecordToIp4Frame(pcapRecord, linkLayerType);
								
								return ipPacket.getFragmentGroupID() == fragmentGroup;
							}).collect(Collectors.toList());
					
					//
					// Remove all defragmented PCAP records.
					//
					
					this.fragmentsList.removeAll(groupedRecords);
					
					resultRecords.addAll(groupedRecords);
				}
			}
			else {
			
				//
				// IP packet is not fragmented. Execute handler code for TCP and UDP payloads.
				//
				
				if (this.tcpHandler != null && ip.getProtocol() == Ip4Frame.PROTO_TCP) {
					
					final TcpPacket tcp = new TcpPacket(ip.getPayload());
					
					this.tcpHandler.accept(tcp);
				}
				
				if (this.udpHandler != null && ip.getProtocol() == Ip4Frame.PROTO_UDP) {
					
					final UdpDatagram udp = new UdpDatagram(ip.getPayload());
					
					this.udpHandler.accept(udp);
				}
				
				resultRecords.add(record);
			}
		}
	
		return resultRecords;
	}

	/**
	 * Assign handler (callback function) that will be executed on each IPv4 packet.
	 * <p>
	 * Handler will simply accept as argument {@link Ip4Frame}.
	 * 
	 * @param handler	-	instance of {@link Consumer} interface implementation 
	 */
	public void setIp4Handler(final Consumer<Ip4Frame> handler) {
		
		this.ipHandler = handler;
	}

	/**
	 * Assign handler (callback function) that will be executed on each TCP packet.
	 * <p>
	 * Handler will simply accept as argument {@link TcpPacket}.
	 * 
	 * @param handler	-	instance of {@link Consumer} interface implementation 
	 */	
	public void setTcpHandler(final Consumer<TcpPacket> handler) {
		
		this.tcpHandler = handler;
	}

	/**
	 * Assign handler (callback function) that will be executed on each (assembled) UDP datagram packet.
	 * <p>
	 * Handler will simply accept as argument {@link UdpDatagram}.
	 * 
	 * @param handler	-	instance of {@link Consumer} interface implementation 
	 */
	public void setUdpHandler(final Consumer<UdpDatagram> handler) {
		
		this.udpHandler = handler;
	}

	@Override
	public void close() throws IOException {
		
		this.in.close();
	}
	
	/**
	 * Extract an {@link Ip4Frame} packet from PCAP record.
	 * 
	 * @param record		-	PCAP record, see {@link PcapRecordHeader}
	 * @param linkLayerType	-	link layer type, obtained from {@link PcapGlobalHeader#getNetwork()} method
	 *  
	 * @return {@link Ip4Frame} packet, or null value if error occurs
	 */
	public static Ip4Frame convertPcapRecordToIp4Frame(final PcapRecordHeader record, final int linkLayerType) {

		try {

			final byte[] ipv4Payload;

			if (linkLayerType == LinkLayerType.LINKTYPE_ETHERNET) {

				final EthernetFrame ethernet = new EthernetFrame(record.getPayload());
				ipv4Payload = ethernet.getPayload();
			}
			else if (linkLayerType == LinkLayerType.LINKTYPE_LINUX_SLL) {

				final LinuxCookedFrame cooked = new LinuxCookedFrame(record.getPayload());
				ipv4Payload = cooked.getPayload();								
			}
			else {

				return null;
			}

			return new Ip4Frame(ipv4Payload);
		}
		catch (final IOException ex) {

			return null;
		}
	}

	/**
	 * Access to {@link PcapGlobalHeader} structure that holds information
	 * like link layer type, etc.
	 * 
	 * @return	{@link PcapGlobalHeader} structure, or null value if reading of PCAP file did not start
	 */
	public PcapGlobalHeader getPcapGlobalHeader() {
		
		return this.globalHeader;
	}
}
