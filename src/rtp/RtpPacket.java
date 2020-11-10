package rtp;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * This class is used to represent raw bytes as RTP packet (RTP header + payload) and also to
 * build raw bytes from instance of {@link RtpPacket} class.
 *   
 *
 */
public class RtpPacket {

	/**
	 * Speex payload type is dynamic. This program use code value 110.
	 * 
	 * See {@link SipMessageBuilder} class where SDP message 
	 *  with dynamic port mapping is generated.
	 */
	public static final byte PT_SPEEX_8000 = 110;

	/**
	 *  Custom - used for transcoding.
	 */			
	public static final byte PT_L16_8000 = -2;

	/**
	 *  Supported codecs: <A HREF=http://tools.ietf.org/html/rfc3551#section-6>rfc3551</A>.
	 */
	public static final byte PT_PCMU = 0, PT_GSM = 3, PT_PCMA = 8, PT_G729 = 18, PT_Unknown_19 = 19, PT_dynamic_96 = 96;

	/**
	 * Minimum RTP header length.
	 */
	public static final int RTP_HEADER_LEN = 12;
	
	/**
	 * RTP version value.
	 * Ref. <A HREF=https://en.wikipedia.org/wiki/Real-time_Transport_Protocol#Packet_header>RTP on Wikipedia</A>
	 */
	public static final int CURRENT_RTP_VER = 2;

	/**
	 * Bits 7. and 6. in first byte represent RTP header version. Currently only ver. 2 is supported.
	 */
	private byte version;

	/**
	 * First byte, 5. bit in RTP header is padding bit.
	 */
	private boolean padding;

	/**
	 * First byte, 4. bit in RTP header is extension bit.
	 */
	private boolean extension;

	/**
	 * First byte, bits 0, 1, 2 and 3 in RTP header are contributing source identifier count.
	 */
	private byte cc;

	/**
	 * Second byte, bit 7. is marker if it is first RTP packet or not.
	 */
	private boolean marker;

	/**
	 * Second byte, all bits from bit 0 to bit 6 form payload type value.
	 */
	private byte payloadType;

	/**
	 * Sequence number value is in third and fourth bytes.
	 */
	private int seqNum;

	/**
	 * Timestamp is 32-bit value, next four bytes it takes.
	 */
	private long timestamp;

	/**
	 * Stream identifier is also next four bytes.
	 */
	private long ssrc;

	/**
	 * List of contributing ssrc streams.
	 */
	private long csrc[] = null;

	/**
	 * Raw byte buffer for payload.
	 */
	private byte payload[] = null;
	
	/**
	 * Encapsulated byte buffer for payload.
	 */
	private ByteBuffer payloadBuffer = null;

	/**
	 * New instance of RTP packet.
	 * 
	 * @param data			-	byte array buffer with RTP header and payload
	 * 
	 * @throws IOException	if byte array contains invalid data
	 */
	public RtpPacket(final byte[] data) throws IOException {

		if (data == null || data.length == 0) {
			
			throw new IOException("No data.");
		}

		if (data.length < RTP_HEADER_LEN) {
			
			throw new IOException("RTP header too short: " + data.length + " bytes in length.");
		}
		
		short verPadExtCC = data[0];

		version   = (byte) ((verPadExtCC & 0xC0) >>> 6);
		padding   = ((verPadExtCC & 0x20) == 0x20) ? true : false;
		extension = ((verPadExtCC & 0x10) == 0x10) ? true : false;
		cc        = (byte) (verPadExtCC & 0x7F);

		if (version != CURRENT_RTP_VER) {
			throw new IOException("RTP header invalid version value: " + version + ". Expected version value: " + CURRENT_RTP_VER);
		}
		
		short markerPayloadType = data[1];
		marker      = ((markerPayloadType & 0x80) == 0x80) ? true : false;
		payloadType = (byte) (markerPayloadType & 0x7F);

		seqNum    = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF); 
		timestamp = data[4] << 24 | (data[5] & 0xFF) << 16 | (data[6] & 0xFF)  << 8 | (data[7] & 0xFF);
		ssrc      = data[8] << 24 | (data[9] & 0xFF) << 16 | (data[10] & 0xFF) << 8 | (data[11] & 0xFF);

		// This will ensure that SSRC and timestamp are not negative.
		ssrc = ssrc & Long.MAX_VALUE; 
		timestamp = timestamp & Long.MAX_VALUE;
		
		if (getCc() > 0) {
			csrc = new long[getCc()];
			for(int i=0; i < getCc(); ++i) {
				csrc[i] = data[12 + i] << 24 | (data[13 + i] & 0xFF) << 16 | (data[14 + i] & 0xFF) << 8 | (data[15 + i] & 0xFF);
			}
		}

		if (data.length > RTP_HEADER_LEN + 4 * getCc()) {
			int payloadLen = data.length - RTP_HEADER_LEN + 4 * getCc();
			payload = new byte[payloadLen];
			System.arraycopy(data, RTP_HEADER_LEN + 4 * getCc(), payload, 0, payloadLen);
			payloadBuffer = ByteBuffer.wrap(payload); 
		}
		
	}
	
	/**
	 * New instance of RTP packet.
	 * 
	 * @param packet			-	byte buffer {@link ByteBuffer}, with RTP header and payload
	 * 
	 * @throws IOException	if byte array contains invalid data
	 */
	public RtpPacket(final ByteBuffer packet) throws IOException {

		if (packet == null || packet.capacity() == 0) {
			throw new IOException("No data.");
		}

		if (packet.capacity() < RTP_HEADER_LEN) {
			throw new IOException("RTP header too short: " + packet.capacity() + " bytes in length.");
		}
		
		byte verPadExtCC = packet.get();

		version   = (byte) ((verPadExtCC & 0xC0) >>> 6);
		padding   = ((verPadExtCC & 0x20) == 0x20) ? true : false;
		extension = ((verPadExtCC & 0x10) == 0x10) ? true : false;
		cc        = (byte) (verPadExtCC & 0x7F);

		if (version != CURRENT_RTP_VER) {
			throw new IOException("RTP header invalid version value: " + version + ". Expected version value: " + CURRENT_RTP_VER);
		}
		
		byte markerPayloadType = packet.get();
		marker      = ((markerPayloadType & 0x80) == 0x80) ? true : false;
		payloadType = (byte) (markerPayloadType & 0x7F);

		seqNum    = 0xFFFF & packet.getShort(); 
		timestamp = packet.getInt();
		ssrc      = packet.getInt();
		
		// This will ensure that SSRC and timestamp are not negative.
		ssrc = ssrc & Long.MAX_VALUE; 
		timestamp = timestamp & Long.MAX_VALUE;
		
		if (getCc() > 0) {
			csrc = new long[getCc()];
			for(int i=0; i < getCc(); ++i) {
				csrc[i] = packet.getInt();
			}
		}

		payloadBuffer = packet.slice();
		
	}	

	/**
	 * Get string from payload type value.
	 * 
	 * @param payloadType	-	one of {@link #PT_G729}, {@link #PT_GSM}, {@link #PT_PCMA}, {@link #PT_PCMU}, ...
	 * 
	 * @return G711uLaw, G711ALaw, Speex, ... or unknown
	 */
	public static String getPayloadTypeName(final int payloadType) {

		switch (payloadType) {
		case PT_PCMU:
			
			return "G711uLaw";
		case PT_PCMA:
			
			return "G711ALaw";
		case PT_G729:
			
			return "G729";
		case PT_L16_8000:
			
			return "L16";
		case PT_SPEEX_8000:
			
			return "Speex";
		case PT_GSM:
			
			return "GSM";
		default:
			
			return "unknown";
		}
	}

	/**
	 * RTP version in header.
	 * 
	 * @return should be value 2 always
	 */
	public byte getVersion() {
		
		return version;
	}

	/**
	 * Is padding bit set.
	 * 
	 * @return padding bit
	 */
	public boolean isPadding() {
		
		return padding;
	}

	/**
	 * Is extension bit set.
	 * 
	 * @return	extension bit
	 */
	public boolean isExtension() {
		
		return extension;
	}

	/**
	 * Contributing source stream identifier value.
	 * 
	 * @return	contributing source stream identifier 
	 */
	public byte getCc() {
		
		return cc;
	}

	/**
	 * Marker if this is first RTP packet in stream.
	 * 
	 * @return	marker bit
	 */
	public boolean isMarker() {
		
		return marker;
	}

	/**
	 * Payload type for this packet.
	 * 
	 * @return	payload value, see {@link RtpPacket#PT_G729}, {@link RtpPacket#PT_PCMA}, ...
	 */
	public byte getPayloadType() {
		
		return payloadType;
	}

	/**
	 * Sequence number of this packet.
	 * 
	 * @return	seq. number
	 */
	public int getSeqNum() {
		
		return seqNum;
	}

	/**
	 * Timestamp value is random value which is assigned to first RTP packet in stream and then incremented by number of audio samples
	 * in payload of packet.
	 * 
	 * @return	RTP packet timestamp value 
	 */
	public long getTimestamp() {
		
		return timestamp & Long.MAX_VALUE;
	}

	/**
	 * Get SSRC value for this stream.
	 * 
	 * @return	ssrc value
	 */
	public long getSsrc() {
		
		return ssrc & Long.MAX_VALUE;
	}

	/**
	 * Additional SSRC list.
	 * 
	 * @return	contributing list of SSRCs
	 */
	public long[] getCsrc() {
		
		return csrc;
	}
	
	/**
	 * Return payload buffer.
	 * 
	 * @return	RTP packet payload
	 */
	public byte[] getPayload() {
		
		if (payload == null && payloadBuffer != null) {
			
			payload = new byte[payloadBuffer.capacity()];
			payloadBuffer.get(payload);
			
			return payload;
			
		}
		
		return payload;
	}

	/**
	 * Get payload wrapped in {@link ByteBuffer) instance.
	 * 
	 * @return	payload
	 */
	public ByteBuffer getPayloadByteBuffer() {
		
		if (payloadBuffer != null) {
			return payloadBuffer.asReadOnlyBuffer();
		}
		else if (payload != null) {
			return ByteBuffer.wrap(payload);
		}
		else {
			return null;
		}
		
	}
	
	/**
	 * Get payload length in bytes.
	 * 
	 * @return payload length
	 */
	public int getPayloadSize() {
		
		if (payload != null) {
			return payload.length;
		}
		
		if (payloadBuffer != null) {
			return payloadBuffer.capacity();
		}
		
		return 0;
	}
	
	/**
	 * Helper method tu build byte array which represents an RTP packet.
	 * 
	 * @param marker
	 * @param payloadType
	 * @param seqNum
	 * @param timeStamp
	 * @param ssrc
	 * @param payload
	 * 
	 * @return	byte array that can be passed to {@link RtpPacket#RtpPacket(byte[])} constructor
	 */
	public static byte[] build(
			final boolean marker,
			final byte payloadType,
			final short seqNum,
			final int timeStamp,
			final int ssrc,
			final byte[] payload) {
		
		final byte[] result = new byte[12 + payload.length];
		
		final ByteBuffer buffer = ByteBuffer.wrap(result);
		
		buffer.put( (byte) 0x80); // Set ver. 2, padding and extension to 0, and csrc also to 0.
		
		if (marker) {
		
			buffer.put( (byte) ((0x80) | (payloadType & 0x7F)) );
		}
		else {
			
			buffer.put( (byte) (payloadType & 0x7F) );
		}
		
		buffer.putShort(seqNum);
		buffer.putInt(timeStamp);
		buffer.putInt(ssrc);
		
		buffer.put(payload);
		
		return result;
	}
}