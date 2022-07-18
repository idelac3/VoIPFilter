package packet;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Ethernet frame decoder with support for single VLAN tag.
 *
 */
public class EthernetFrame {
	
	/**
	 * Some typical ethernet types. See
	 *  https://en.wikipedia.org/wiki/EtherType
	 * for more information.
	 */
	public static int ETHERTYPE_IPv4 = 0x0800
			, ETHERTYPE_ARP = 0x0806
			, ETHERTYPE_VLAN = 0x8100
			, ETHERTYPE_IPv6 = 0x86DD;
			
	/**
	 * Destination and source MAC address. 
	 */
	private byte[] dst_mac = new byte[6], src_mac = new byte[6];
	
	/**
	 * Ethernet type.
	 */
	private int ethertype = -1;
	
	/**
	 * Flag if frame has VLAN tag.
	 */
	private int vlan = -1;
	
	/**
	 * Payload data of Ethernet frame.
	 */
	private byte[] payload = null;

	/**
	 * Payload data of Ethernet frame.
	 */
	private ByteBuffer payloadByteBuffer = null;

	/**
	 * Provide bytes that represent Ethernet frame.
	 * 
	 * @param frame - input bytes
	 * 
	 * @throws IOException
	 */
	public EthernetFrame(byte[] frame) throws IOException {
		
		System.arraycopy(frame, 0, dst_mac, 0, 6);
		System.arraycopy(frame, 6, src_mac, 0, 6);
				
		ethertype = (frame[12] << 8) | frame[13];
		ethertype = ethertype & 0xFFFF;
		
		if (ethertype == 0x8100) {
			
			// VLAN tagged frame.
			vlan = (frame[14] << 8) | frame[15];
			vlan = vlan & 0xFFFF;
			
			ethertype = (frame[16] << 8) | frame[17];
			ethertype = ethertype & 0xFFFF;
			
		}
		
		int payloadSize = frame.length - 6 - 6 - 2;
		if (vlan != -1) {
			payloadSize = payloadSize - 4;
		}
		
		payload = new byte[payloadSize];
		int offset = frame.length - payloadSize;
		System.arraycopy(frame, offset, payload, 0, payloadSize);
		
	}
		
	/**
	 * Provide bytes that represent Ethernet frame.
	 * 
	 * @param frame - input bytes as {@link ByteBuffer}
	 * 
	 * @throws IOException
	 */
	public EthernetFrame(final ByteBuffer frame) throws IOException {
		
		if (frame.capacity() <= 14 ) {
			
			throw new IOException(
					String.format("Unable to decode ethernet frame from data in buffer. Buffer only %d bytes."
							, frame.capacity()));
		}
		
		frame.get(dst_mac);
		frame.get(src_mac);
				
		ethertype = frame.getShort();
		
		if (ethertype == 0x8100) {
			
			// VLAN tagged frame.
			vlan = frame.getShort();
			
			ethertype = frame.getShort();
			
		}
		
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
	 * Get Ethernet frame payload size.
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
	 * Ethernet type. Used to determine next header.
	 * <br>
	 * See
	 *  <a href="https://en.wikipedia.org/wiki/EtherType">EtherTypes</a>
	 * for possible values.
	 *  
	 * @return Ethernet type
	 */
	public int getEthertype() {		
		
		return ethertype;
	}

	/**
	 * Destination MAC address.
	 * 
	 * @return destination MAC address in format xx:xx:xx:yy:yy:yy
	 */
	public String getDstMAC() {	
		
		return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
				dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
	}
	
	/**
	 * Source MAC address.
	 * 
	 * @return source MAC address in format xx:xx:xx:yy:yy:yy
	 */
	public String getSrcMAC() {		
		
		return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
				src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
	}
	
}
