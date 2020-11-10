package packet;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Record header as described in:<br>
 * <a href="https://wiki.wireshark.org/Development/LibpcapFileFormat">Pcap format</a><br>
 * This implementation supports only <B>tcpdump</B> generated header. PCAPNG and other header 
 * formats are not supported.
 *
 */
public class PcapRecordHeader {
	
	private int ts_sec    = 0;
	private int ts_usec   = 0;
	private int incl_len = 0;
	private int orig_len  = 0;
	
	private byte[] payload = null;
	
	private boolean swap = false;
	
	/**
	 * Read record header from {@link DataInputStream} source.
	 * 
	 * @param in - data input stream source
	 * @param swapped - indicator if bytes should be swapped or not (little endian vs. big endian byte ordering)
	 * @throws IOException
	 */
	public PcapRecordHeader(final DataInputStream in, final boolean swapped) throws IOException {
		
		this.swap = swapped;
		
		ts_sec    = in.readInt();
		ts_usec   = in.readInt();
		incl_len  = in.readInt();
		orig_len  = in.readInt();
	
		payload = new byte[getIncl_len()];
		in.read(payload);
		
	}
	
	/**
	 * Get payload, typically complete Ethernet frame.
	 * 
	 * @return complete packet including all data
	 */
	public byte[] getPayload() {
		return payload;
	}
	
	/**
	 * Get payload, typically complete Ethernet frame.
	 * 
	 * @return complete packet including all data
	 */
	public ByteBuffer getPayloadByteBuffer() {
		return ByteBuffer.wrap(payload);
	}
	
	private static int swap32(int value) {
		
		int ret = 0x0FF & value;

		ret <<= 8;
		value >>= 8;
		
		ret |= 0x0FF & value;
		ret <<= 8;

		value >>= 8;
		ret |= 0x0FF & value;
		ret <<= 8;

		value >>= 8;
		ret |= 0x0FF & value;

		return ret;
		
	}
	
	/**
	 * The date and time when this packet was captured. This value is in seconds since January 1, 1970 00:00:00 GMT.
	 * This is also known as a UN*X time_t. If this timestamp isn't based on GMT (UTC), use thiszone from the global header for adjustments.
	 * 
	 * @return date & time when packet is captured
	 */
	public int getTs_sec() {
		if (swap) {
			return swap32(ts_sec);
		}
		return ts_sec;
	}

	/**
	 * In regular pcap files, the microseconds when this packet was captured, as an offset to ts_sec.
	 * In nanosecond-resolution files, this is, instead, the nanoseconds when the packet was captured,
	 * as an offset to ts_sec.
	 * <B>Beware:</B> this value shouldn't reach 1 second ! <BR>
	 * In regular pcap files 1 000 000; in nanosecond-resolution files, 1 000 000 000); 
	 * In this case ts_sec must be increased instead!
	 * 
	 * @return in nano seconds, offset to {@link #getTs_sec()} value
	 */
	public int getTs_usec() {
		if (swap) {
			return swap32(ts_usec);
		}
		return ts_usec;
	}
	
	/**
	 * The number of bytes of packet data actually captured and saved in the file.
	 * This value should never become larger than orig_len or the snaplen value of the global header.
	 * 
	 * @return actual size of saved packet data
	 */
	public int getIncl_len() {
		if (swap) {
			return swap32(incl_len);
		}
		return incl_len;
	}

	/**
	 * The length of the packet as it appeared on the network when it was captured.
	 * If {@link #getIncl_len()} and {@link #getOrig_len()} differ, the actually saved packet size was limited by {@link PcapGlobalHeader#getSnaplen()}.
	 * 
	 * @return length of packet as seen on network
	 */
	public int getOrig_len() {
		if (swap) {
			return swap32(orig_len);
		}
		return orig_len;
	}

	/**
	 * PCAP record (including payload).
	 * 
	 * @param	withPayload		-	flag to determine if only record header is needed 
	 * 								or complete record with packet
	 * 
	 * @return	raw byte[] representation of PCAP record with payload
	 */
	public byte[] toByteArray(boolean withPayload) {
		
		final byte[] pcapRecord = new byte[16];
		final ByteBuffer buf = ByteBuffer.wrap(pcapRecord);
		
		buf.putInt(ts_sec);
		buf.putInt(ts_usec); 
		buf.putInt(incl_len);
		buf.putInt(orig_len);
			
		if (withPayload == true) {
		
			buf.put(payload);
		}			
	
		return pcapRecord;
	}
	
	/**
	 * Build PCAP record (header only).
	 * 
	 * @param	ts_sec	-	time stamp major part, seconds
	 * @param	ts_usec	-	tims stamp minor part, microseconds
	 * 
	 * @param	inclLen	-	stored length of PCAP record
	 * @param	origLen	-	original length, 
	 * 						in case that stored length of packet is smaller than original packet size 
	 * 
	 * @return	raw byte[] representation of PCAP record header
	 */
	public static byte[] toByteArray(final boolean swapped
			, final int ts_sec, final int ts_usec
			, final int inclLen, final int origLen) {
	
		
		final byte[] pcapRecord = new byte[16];
		final ByteBuffer buf = ByteBuffer.wrap(pcapRecord);
		
		for (int value : new int[] {ts_sec, ts_usec, inclLen, origLen}) {
			
			if (swapped == true) {
				
				buf.putInt(swap32(value));
			}
			else {
				
				buf.putInt(value);
			}
		}
	
		return pcapRecord;
	}
}
