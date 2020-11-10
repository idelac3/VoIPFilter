package packet;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * 
 * IPv4 header decoder.
 *
 */
public class Ip4Frame {
	
	/**
	 * Some typical transport protocol values found in IPv4 packet header.
	 */
	final public static int PROTO_ICMP = 1 //	Internet Control Message Protocol	ICMP
			, PROTO_IGMP =	2 //	Internet Group Management Protocol	IGMP
			, PROTO_TCP =	6 //	Transmission Control Protocol	TCP
			, PROTO_UDP =  17 //	User Datagram Protocol	UDP
			, PROTO_IPv6 =  41 //	IPv6 encapsulation	ENCAP
			, PROTO_OSPF = 89 //	Open Shortest Path First	OSPF
			, PROTO_SCTP =	132	// Stream Control Transmission Protocol	SCTP
	;
	
	/**
	 * Destination IP address as 4-byte network order data.
	 */
	private byte[] dst = new byte[4];
	
	/**
	 * Source IP address as 4-byte network order data.
	 */
	private byte[] src = new byte[4];
	
	/**
	 * IP Version.
	 */
	private int ver = 0;
	
	/**
	 * Time to live value.
	 */
	private byte ttl = 0;
	
	/**
	 * Protocol type in payload. Usually UDP or TCP.
	 */
	private byte protocol = 0;
	
	/**
	 * IHL, DSCP, and ECN values.
	 */
	private int IHL = 0, DSCP = 0, ECN = 0;

	/**
	 * Payload length.
	 */
	private int totalLength = 0;
	
	/**
	 * IPv4 packet fragmentation values.
	 */
	private int fragmentGroupID = 0, fragmentFlag = 0, fragmentOffset = 0;
		
	/**
	 * Payload data.
	 */
	private byte[] payload = null;

	/**
	 * Payload data.
	 */
	private ByteBuffer payloadByteBuffer = null;
	
	private byte[] origIPv4Packet = null;
	
	/**
	 * Construct IPv4 frame from byte array.
	 * 
	 * @param packet 	-		raw packet data
	 * 
	 * @throws IOException if IPv4 header is invalid
	 */
	public Ip4Frame(byte[] packet) throws IOException {
		
		// Dummy way how to save original packet as byte array.
		this.origIPv4Packet = packet;
		
		ver = (packet[0] & 0xF0) >> 4;
		IHL = packet[0] & 0x0F;
		DSCP = packet[1] >> 2;
		ECN  = packet[1] & 0x03;
		
		totalLength = (packet[2] << 8) | (packet[3] & 0xFF);
		totalLength = totalLength & 0xFFFF;
		
		fragmentGroupID = (packet[4] << 8) | (packet[5] & 0xFF);
		fragmentFlag    = (packet[6] >> 5) & 0x03;
		fragmentOffset  = ((packet[6] << 8) | (packet[7] & 0xFF)) & 0x1FFF;
		
		ttl = packet[8];
		protocol = packet[9];
		
		System.arraycopy(packet, 12, src, 0, 4);
		System.arraycopy(packet, 16, dst, 0, 4);
		
		int headerLen = IHL * 4;
		
		if (totalLength - headerLen > 0) {
			payload = new byte[totalLength - headerLen];
			System.arraycopy(packet, headerLen, payload, 0, payload.length);
		}
	}

	/**
	 * Construct IPv4 frame from byte buffer.
	 * 
	 * @param packet 	-	packet data {@link ByteBuffer} instance
	 * 
	 * @throws IOException if IPv4 header is invalid
	 */
	public Ip4Frame(final ByteBuffer packet) throws IOException {
		
		byte tmpByte = packet.get();
		ver = (tmpByte & 0xF0) >> 4;
		IHL = tmpByte & 0x0F;
		
		tmpByte = packet.get();
		DSCP = tmpByte >> 2;
		ECN  = tmpByte & 0x03;
		
		totalLength = 0xFFFF & packet.getShort();
		
		fragmentGroupID = packet.getShort();
		fragmentOffset  = packet.getShort();
		fragmentFlag    = (fragmentOffset >> 13) & 0x03;
		fragmentOffset  = fragmentOffset & 0x1FFF;
	
		ttl = packet.get();
		protocol = packet.get();
		
		packet.getShort();
		
		packet.get(src);
		packet.get(dst);
		
		int headerLen = IHL * 4;
		
		int payloadLen = totalLength - headerLen;
		if (payloadLen > 0) {
			payloadByteBuffer = packet.slice();
			
			if (payloadByteBuffer.capacity() > payloadLen) {
				payload = new byte[payloadLen];
				payloadByteBuffer.get(payload);
				payloadByteBuffer = ByteBuffer.wrap(payload);
			}
		}
	}

	/**
	 * Get payload as byte array.
	 * 
	 * @return payload
	 */
	public byte[] getPayload() {
		
		return payload;
	}

	/**
	 * Get payload as {@link ByteBuffer}.
	 * 
	 * @return payload as ByteBuffer
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
	 * Get payload size.
	 * 
	 * @return payload or 0 if no payload is present
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
	 * IP version value. Should be value 4.
	 * 
	 * @return IP version value
	 */
	public int getVersion() {
		
		return ver;
	}

	/**
	 * Time-to-live value.
	 * 
	 * @return value between 1..255, 
	 *  decremented by router each time IP packet is routed
	 *  
	 */
	public int getTTL() {
		
		return ttl;
	}

	/**
	 * Transport level protocol, eg. UDP or TCP.
	 * 
	 * @return
	 */
	public int getProtocol() {
		
		return protocol;
	}

	/**
	 * Source IP address.
	 * 
	 * @return IP address as byte array, network byte order
	 */
	public byte[] getSrcAddress() {		
		
		return src;
	}

	/**
	 * Destination IP address.
	 * 
	 * @return destination IP address as byte array, network byte order
	 */
	public byte[] getDstAddress() {	
		
		return dst;
	}

	/**
	 * Source IP address as string in doted decimal format.
	 * 
	 * @return destination IP address in human readable format
	 * 
	 * @throws UnknownHostException
	 */
	public String getSrc() throws UnknownHostException {
		
		return Inet4Address.getByAddress(src).getHostAddress();
	}

	/**
	 * Destination IP address as string in doted decimal format.
	 * 
	 * @return	destination IP address in human readable format
	 * 
	 * @throws UnknownHostException
	 */
	public String getDst() throws UnknownHostException {
		
		return Inet4Address.getByAddress(dst).getHostAddress();
	}

	/**
	 * IPv4 packet length from header value obtained.
	 * 
	 * @return packet length header value
	 */
	public int getTotalLength() {
		
		return totalLength;
	}

	/**
	 * DSCP value.
	 * 
	 * @return
	 */
	public int getDSCP() {
		
		return DSCP;
	}
	
	/**
	 * ECN value.
	 * 
	 * @return
	 */
	public int getECN() {
		
		return ECN;
	}

	/**
	 * Fragment group value.
	 * 
	 * @return
	 */
	public int getFragmentGroupID() {
		
		return fragmentGroupID;
	}

	/**
	 * Fragment flag.
	 * 
	 * @return
	 */
	public int getFragmentFlag() {
		
		return fragmentFlag;
	}

	/**
	 * Fragment offset.
	 * 
	 * @return
	 */
	public int getFragmentOffset() {
		
		return fragmentOffset;
	}

	/**
	 * Handy method to turn back {@link Ip4Frame} object into byte array.
	 * 
	 * @param	ip		-	{@link Ip4Frame} 
	 * @return	raw IPv4 packet including/with payload
	 */
	public static byte[] toByteArray(final Ip4Frame ip) {

		return ip.origIPv4Packet;
	}
}
