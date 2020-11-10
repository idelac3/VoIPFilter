package packet;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * TCP packet.
 *
 */
public class TcpPacket {
	
	/**
	 * Source and destination port.
	 */
	private int dst_port = 0, src_port = 0;
	
	/**
	 * Seq.num and ack.num. values.
	 */
	private int seq = -1, ack = -1;
	
	/**
	 * Data offset, flags and window size.
	 */
	private int data_offset = 0, flags = 0, window_size = -1;
	
	/**
	 * Checksum and urgent pointer.
	 */
	private int checksum = 0, urg = 0;
	
	/**
	 * Payload bytes.
	 */
	private byte[] payload = null;

	/**
	 * Payload bytes.
	 */
	private ByteBuffer payloadByteBuffer = null;

	/**
	 * Construct TCP packet from raw bytes.
	 * 
	 * @param packet
	 * @throws IOException
	 */
	public TcpPacket(byte[] packet) throws IOException {
		
		if (packet.length >= 20) {
			
			src_port = ((packet[0] & 0xFF) << 8) | (packet[1] & 0xFF);
			dst_port = ((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF);
			
			seq      = ((packet[4] & 0xFF) << 24) | ((packet[5] & 0xFF) << 16)
					| ((packet[6] & 0xFF) <<   8) | ((packet[7] & 0xFF));
			ack      = ((packet[8] & 0xFF) << 24) | ((packet[9] & 0xFF) << 16)
					| ((packet[10] & 0xFF) <<   8) | ((packet[11] & 0xFF));

			data_offset = (packet[12] & 0xF0) >> 4;

			flags       = ((packet[12] & 0x01) << 8) | (packet[13] & 0xFF);

			window_size = ((packet[14] & 0xFF) << 8) | (packet[15] & 0xFF);

			checksum = ((packet[16] & 0xFF) << 8) | (packet[17] & 0xFF);
			urg      = ((packet[18] & 0xFF) << 8) | (packet[19] & 0xFF);

		
			int payload_offset = data_offset * 4;
			
			int payloadLen = packet.length - payload_offset;
			
			if (payloadLen > 0) {
				payload = new byte[packet.length - payload_offset];
				System.arraycopy(packet, payload_offset, payload, 0, packet.length - payload_offset);
			}
			
		}
		else {
			throw new IOException("TCP packet size too small: " + packet.length + " bytes only.");
		}
		
	}
	
	/**
	 * Construct TCP packet from raw bytes.
	 * 
	 * @param packet
	 * @throws IOException
	 */
	public TcpPacket(ByteBuffer packet) throws IOException {
		
		if (packet.capacity() >= 20) {
			
			src_port = packet.getShort() & 0xFFFF;
			dst_port = packet.getShort() & 0xFFFF;
			
			seq      = packet.getInt();
			ack      = packet.getInt();					

			flags       = packet.getShort();
			data_offset = (flags >> 12) & 0x000F; 
			flags       = flags & 0x01FF;
			
			window_size = packet.getShort() & 0xFFFF;

			checksum = packet.getShort();
			urg      = packet.getShort();
		
			int payload_offset = data_offset * 4;
			
			int payloadLen = packet.capacity() - payload_offset;
			
			if (payloadLen > 0) {
				payloadByteBuffer = packet.slice();				
			}
			
		}
		else {
			throw new IOException("TCP packet size too small: " + packet.capacity() + " bytes only.");
		}
		
	}
	
	/**
	 * Payload data.
	 * 
	 * @return
	 */
	public byte[] getPayload() {
		return payload;
	}
	
	/**
	 * Payload data.
	 * 
	 * @return
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
	 * Get checksum value.
	 * 
	 * @return
	 */
	public int getChecksum() {
		return checksum;
	}
	
	/**
	 * Get source port value.
	 * 
	 * @return
	 */
	public int getSrcPort() {		
		return src_port;
	}
	
	/**
	 * Get destination port value.
	 * 
	 * @return
	 */
	public int getDstPort() {		
		return dst_port;
	}
	
	/**
	 * Get flags. First 9 bits are valid. Rest should be 0.
	 * 
	 * @return
	 */
	public int getFlags() {		
		return flags;
	}

	/**
	 * Get seq.num. value as 4-byte integer value. Might return negative also.
	 * 
	 * @return
	 */
	public int getSeq() {		
		return seq;
	}

	/**
	 * Get seq.num. value as positive long value.
	 * 
	 * @return
	 */	
	public long getSeqNum() {
		return (long)seq & 0x00000000FFFFFFFFL; 
	}

	/**
	 * Get ACK value as 4-byte integer value. Might return negative also.
	 * 
	 * @return
	 */
	public int getAck() {		
		return ack;
	}
	
	/**
	 * Get ACK value as positive long value.
	 * 
	 * @return
	 */
	public long getAckNum() {
		return (long)ack & 0x00000000FFFFFFFFL; 
	}
	
	/**
	 * Get urgent pointer.
	 * 
	 * @return
	 */
	public int getUrg() {		
		return urg;
	}
	
	/**
	 * Get window size.
	 * 
	 * @return
	 */
	public int getWindowSize() {		
		return window_size;
	}
	
	/**
	 * Check for SYN flag.
	 * 
	 * @return
	 */
	public boolean isSYN() {
		return (flags & 0x02) == 0x02;
	}
	
	/**
	 * Check for ACK flag.
	 * 
	 * @return
	 */
	public boolean isACK() {
		return (flags & 0x10) == 0x10;
	}
	
	/**
	 * Check for FIN flag.
	 * 
	 * @return
	 */
	public boolean isFIN() {
		return (flags & 0x01) == 0x01;
	}
	
	/**
	 * Check for PSH flag.
	 * 
	 * @return
	 */
	public boolean isPSH() {
		return (flags & 0x08) == 0x08;
	}

	/**
	 * Check for RST flag.
	 * 
	 * @return
	 */
	public boolean isRST() {
		return (flags & 0x04) == 0x04;
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
	
	@Override
	public String toString() {
		
		String flags = " [";
		if (isSYN())
			flags += "SYN ";
		if (isFIN())
			flags += "FIN ";
		if (isACK())
			flags += "ACK ";
		if (isPSH())
			flags += "PSH ";
		if (isRST())
			flags += "RST ";
		flags += "] ";

		String srcPort = String.valueOf(getSrcPort());
		if (srcPort.length() < 5) {
			srcPort = "";
			for (int i = 0; i < 5 - srcPort.length(); i++) {
				srcPort += " ";
			}
			srcPort += String.valueOf(getSrcPort());
		}

		String dstPort = String.valueOf(getDstPort());
		if (dstPort.length() < 5) {
			dstPort = "";
			for (int i = 0; i < 5 - dstPort.length(); i++) {
				dstPort += " ";
			}
			dstPort += String.valueOf(getDstPort());
		}

		String retVal = srcPort + " --> " + dstPort + flags + "Seq.num: "
				+ getSeqNum() + " Ack: " + getAckNum() + " Payload len: " + getPayloadLen();
		
		return retVal;
		
	}

}
