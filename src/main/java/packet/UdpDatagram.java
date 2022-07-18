package packet;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * UDP packet decoder.
 */
public class UdpDatagram {
	
	/**
	 * Source and destination port, checksum and length.
	 */
	private int dst_port = 0, src_port = 0, checksum = 0, len = 0;
	
	/**
	 * Payload data.
	 */
	private byte[] payload = null;

	/**
	 * Payload bytes.
	 */
	private ByteBuffer payloadByteBuffer = null;

	/**
	 * New UDP datagram.
	 * 
	 * @param datagram		-	byte array containing UDP header and payload 
	 * 
	 * @throws IOException	if decoding of UDP header fails, due to invalid data in array
	 */
	public UdpDatagram(final byte[] datagram) throws IOException {
		
		if (datagram.length < 8) {
			
			throw new IOException("UDP datagram length is too small: " + datagram.length);
		}
		
		src_port = ((datagram[0] & 0xFF) << 8) | (datagram[1] & 0xFF);
		dst_port = ((datagram[2] & 0xFF) << 8) | (datagram[3] & 0xFF);
		len      = ((datagram[4] & 0xFF) << 8) | (datagram[5] & 0xFF);
		checksum = ((datagram[6] & 0xFF) << 8) | (datagram[7] & 0xFF);
		
		if (len < 0) {
			
			len = Integer.MAX_VALUE & len;
		}
		
		if (len > datagram.length) {
			
			len = datagram.length;
		}
		
		if (len - 8 > 0) {
			
			payload = new byte[len - 8];
			System.arraycopy(datagram, 8, payload, 0, payload.length);
		}
	}
		
	/**
	 * New UDP datagram.
	 * 
	 * @param datagram		-	byte array containing UDP header and payload 
	 * 
	 * @throws IOException	if decoding of UDP header fails, due to invalid data in array
	 */
	public UdpDatagram(final ByteBuffer datagram) throws IOException {
		
		if (datagram.capacity() < 8) {
			
			throw new IOException("UDP datagram length is too small: " + datagram.capacity());
		}
		
		src_port = Integer.MAX_VALUE & datagram.getShort();
		dst_port = Integer.MAX_VALUE & datagram.getShort();
		len      = Integer.MAX_VALUE & datagram.getShort();
		checksum = Integer.MAX_VALUE & datagram.getShort();
		
		if (len < 0) {
			
			len = Integer.MAX_VALUE & len;
		}
		
		if (len > datagram.capacity()) {
			
			len = datagram.capacity();
		}
		
		if (len - 8 > 0) {
			
			payloadByteBuffer = datagram.slice();
		}
	}
	
	/**
	 * Get payload data.
	 * 
	 * @return UDP payload data as byte array
	 */
	public byte[] getPayload() {
		
		return payload;
	}
	
	/**
	 * Payload data.
	 * 
	 * @return {@link ByteBuffer} payload buffer
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
	 * Checksum of UDP packet.
	 * 
	 * @return checksum header value
	 */
	public int getChecksum() {
		
		return checksum;
	}
	
	/**
	 * Source UDP port.
	 * 
	 * @return
	 */
	public int getSrcPort() {	
		
		return src_port;
	}
	
	/**
	 * Destination UDP port.
	 * 
	 * @return
	 */
	public int getDstPort() {	
		
		return dst_port;
	}
	
	/**
	 * UDP datagram header + payload length.
	 * 
	 * @return
	 */
	public int getLength() {	
		
		return len;
	}

	/**
	 * UDP datagram payload length.
	 * 
	 * @return UDP datagram length
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
	
}
