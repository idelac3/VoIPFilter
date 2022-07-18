package packet;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Linux cooked frame decoder.
 * Ref.
 *  <a href="http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html">Linux cooked frame</a>
 */
public class LinuxCookedFrame {
	
	/**
	 * Some typical ethernet types. See
	 *  https://en.wikipedia.org/wiki/EtherType
	 * for more information.
	 */
	public static int ETHERTYPE_IPv4 = 0x0800
			, ETHERTYPE_ARP = 0x0806
			, ETHERTYPE_VLAN = 0x8100
			, ETHERTYPE_IPv6 = 0x86DD;
			
	private int packetType;
	
	private int linkLayerAddressType;
	
	private int linkLayerAddressLen;
	
	private byte[] linkLayerAddress;
	
	/**
	 * Ethernet type protocol. Eg. for IPv4 is 0x8000 value.
	 */
	private int protocol;
	
	/**
	 * Payload data of Linux cooked frame.
	 */
	private byte[] payload = null;

	/**
	 * Payload data of Linux cooked frame.
	 */
	private ByteBuffer payloadByteBuffer = null;

	/**
	 * Provide bytes that represent Linux cooked frame.
	 * 
	 * @param frame - input bytes
	 * 
	 * @throws IOException
	 */
	public LinuxCookedFrame(byte[] frame) throws IOException {
		
		final DataInputStream in = new DataInputStream(
				new ByteArrayInputStream(frame));
		
		this.packetType = in.readUnsignedShort();
		this.linkLayerAddressType = in.readUnsignedShort();
		this.linkLayerAddressLen = in.readUnsignedShort();
				
		this.linkLayerAddress = new byte[this.linkLayerAddressLen];
		
		in.read(this.linkLayerAddress);
		in.readShort(); // Unused
		
		this.protocol = in.readUnsignedShort();
		
		int avail = in.available();
		
		payload = new byte[avail];
		in.read(payload);
	}
		
	/**
	 * Provide bytes that represent Linux cooked frame.
	 * 
	 * @param frame - input bytes as {@link ByteBuffer}
	 * 
	 * @throws IOException
	 */
	public LinuxCookedFrame(final ByteBuffer frame) throws IOException {
		
		if (frame.capacity() <= 6 ) {
			
			throw new IOException(
					String.format("Unable to decode Linux cooked frame from data in buffer. Buffer only %d bytes."
							, frame.capacity()));
		}
		
		this.packetType = frame.getShort();
		this.linkLayerAddressType = frame.getShort();
		this.linkLayerAddressLen = frame.getShort();
				
		this.linkLayerAddress = new byte[this.linkLayerAddressLen];
		frame.get(this.linkLayerAddress);
		
		frame.getShort(); // Unused.
		
		this.protocol = frame.getShort();			
		
		payloadByteBuffer = frame.slice();		
	}
	
	/**
	 * Get payload of Ethernet frame. Usually an Ip4 or Ip6 packet.
	 * 
	 * @return payload data
	 */
	public byte[] getPayload() {
		
		return payload;
	}
		
	/**
	 * Get payload of Ethernet frame. Usually an Ip4 or Ip6 packet.
	 * 
	 * @return payload data
	 */
	public ByteBuffer getPayloadByteBuffer() {
		
		if (payloadByteBuffer != null) {
			
			return payloadByteBuffer.asReadOnlyBuffer();
		}
		else {
			
			return ByteBuffer.wrap(payload);
		}
	}
	
	/**
	 * Get Linux cooked frame payload size.
	 * 
	 * @return should be between 1..1500 usually, or 0 if no payload is present.
	 */
	public int getPayloadLen() {
		
		if (payloadByteBuffer != null) {
			
			return payloadByteBuffer.capacity();
		}
		else if (payload != null) {
			
			return payload.length;
		}		
		else {
			
			return 0;
		}
	}
	
	/**
	 * The packet type field is in network byte order (big-endian); it contains a value that is one of:
	 * <ul>
	 * 	<li>0, if the packet was specifically sent to us by somebody else;</li>
	 *  <li>1, if the packet was broadcast by somebody else;</li>
	 *  <li>2, if the packet was multicast, but not broadcast, by somebody else;</li>
	 *  <li>3, if the packet was sent to somebody else by somebody else;</li>
	 *  <li>4, if the packet was sent by us.</li>
	 * </ul>
	 * See
	 *  <a href="https://en.wikipedia.org/wiki/EtherType">EtherTypes</a>
	 * for possible values.
	 *  
	 * @return packet type
	 */
	public int getPacketType() {		
		
		return this.packetType;
	}

	/**
	 * Usually source or destination MAC address for ethernet link layer type.
	 * 
	 * @return MAC address in format xx:xx:xx:yy:yy:yy
	 */
	public byte[] getLinkLayerAddress() {	
		
		return this.linkLayerAddress;
	}
	
	/**
	 * Protocol. Eg. for IPv4, value is {@link EthernetFrame#ETHERTYPE_IPv4}.
	 * 
	 * @return numeric value that corresponds to ethertype value in {@link EthernetFrame} 
	 */
	public int getProto() {		
		
		return this.protocol;
	}
	
	/**
	 * Return Linux ARPHDR link layer address type.
	 * <p>
	 * See <a href="https://docs.huihoo.com/doxygen/linux/kernel/3.7/uapi_2linux_2if__arp_8h_source.html">if_arp.h</a>
	 * 
	 * @return	usually value 1 for ethernet devices
	 */
	public int getLinkLayerAddressType() {
		
		return this.linkLayerAddressType;
	}
	
	/**
	 * Write new Linux 'cooked' frame header.
	 * 
	 * @param	protocol	-	ethertype protocol value, eg. for IPv4 payload use {@link EthernetFrame#ETHERTYPE_IPv4}
	 * 
	 * @return	raw bytes representing Linux 'cooked' frame (without payload)
	 */
	public static byte[] toByteArray(final int protocol) {
		
		final byte[] cooked = new byte[16];
		
		// Seems that Linux 'cooked' header always use BIG ENDIAN byte order :D
		
		final ByteBuffer buf = ByteBuffer.wrap(cooked);
		buf.putShort((short) 0); 	// Packet type.
		buf.putShort((short) 1);	// LinkLayer address type: 1 - ethernet
		buf.putShort((short) 6);	// LinkLayer address length: 6 bytes - MAC address
		buf.put(new byte[]{ 0, 0, 0, 0, 0, 0}); // Empty MAC address.
		buf.putShort((short) 0);
		buf.putShort( (short) protocol);
		
		return cooked;
	}
}
