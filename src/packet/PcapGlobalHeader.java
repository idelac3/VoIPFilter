package packet;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Global header as described in:<br>
 * <a href="https://wiki.wireshark.org/Development/LibpcapFileFormat">Pcap format</a><br>
 * This implementation supports only <B>tcpdump</B> generated header. PCAPNG and other header 
 * formats are not supported.
 *
 */
public class PcapGlobalHeader {
	
	public static final int MAGIC = 0xa1b2c3d4;
	public static final int MAGIC_SWAPPED = 0xd4c3b2a1;

	/**
	 * PCAP header version, 
	 * consists of major value, and minor value.
	 * Both major and minor take 2 bytes.
	 * <p>
	 * Should be <i>2.4</i> always.
	 */
	public static final int VERSION = 0x00020004
	                       ,VERSION_SWAPPED = 0x02000400;
	
	private int magic    = 0;
	private int version  = 0;
	private int thiszone = 0;
	private int sigfigs  = 0;
	private int snaplen  = 0;
	private int network  = 0;
	
	private boolean swap = false;
	
	/**
	 * PCAP global header reader.
	 * 
	 * @param in - {@link DataInputStream} reader instance
	 * @throws IOException
	 */
	public PcapGlobalHeader(DataInputStream in) throws IOException {
		
		magic = in.readInt();
		if (magic != MAGIC && magic != MAGIC_SWAPPED) {
			throw new IOException(
					"Invalid magic value: " + String.format("0x%x", magic) +
					". Expected value: " + String.format("0x%x", MAGIC_SWAPPED));
		}
	
		if (magic == MAGIC_SWAPPED) {
			swap = true;
		}
		
		version  = in.readInt();
	
		if ( (swap == false && version != VERSION) 
				|| (swap == true && version != VERSION_SWAPPED) ) {
			throw new IOException(
					"Invalid header version value: " + String.format("0x%x", version) +
					". Expected value: " + String.format("0x%x", VERSION));
		}
	
		thiszone = in.readInt();
		sigfigs  = in.readInt();
		snaplen  = in.readInt();
		network  = in.readInt();
		
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

	private static int swap16(int value) {
		
		int a = (value & 0x0000FF00) >>  8;
		int b = (value & 0x000000FF) >>  0;
		
		return (b << 8) | a;
		
	}
	
	/**
	 * Are bytes in header swapped. For little-endian systems, this is <I>true</I>.
	 * 
	 * @return <I>true</I> if bytes are swapped in header
	 */
	public boolean isSwapped() {
		return swap;
	}
	
	/**
	 * Should return ver. 2.4 as current PCAP header version.
	 * 
	 * @return version value
	 */
	public String getVersion() {
		
		int major = 0, minor = 0;
		
		major = (version & 0xFFFF0000) >> 16;
		minor = version & 0x0000FFFF;
		
		if (swap) {
			major = swap16(major);
			minor = swap16(minor);
		}
		
		return major + "." + minor;
	}
	/**
	 * The correction time in seconds between GMT (UTC) and the local timezone of 
	 * the following packet header timestamps.<BR>
	 * Examples:<BR>
	 * If the timestamps are in GMT (UTC), thiszone is simply 0. 
	 * If the timestamps are in Central European time (Amsterdam, Berlin, ...) which is GMT + 1:00,
	 * thiszone must be -3600. In practice, time stamps are always in GMT, so thiszone is always 0.
	 * 
	 * @return correction time in seconds
	 */
	public int getThisZone() {
		if (swap) {
			return swap32(thiszone);
		}
		return thiszone;
	}

	/**
	 * In theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0.
	 * 
	 * @return 0
	 */
	public int getSigfigs() {
		if (swap) {
			return swap32(sigfigs);
		}
		return sigfigs;
	}
	
	/**
	 * The "snapshot length" for the capture (typically 65535 or even more, but might be limited by the user).
	 * See: {@link PcapRecordHeader#getIncl_len()} vs. {@link PcapRecordHeader#getOrig_len()}
	 * 
	 * @return
	 */
	public int getSnaplen() {
		if (swap) {
			return swap32(snaplen);
		}
		return snaplen;
	}

	/**
	 * Link-layer header type, specifying the type of headers at the beginning of the packet.
	 * E.g. 1 for Ethernet, see <a href="http://www.tcpdump.org/linktypes.html">tcpdump.org's link-layer header types</a> page for details.
	 * This can be various types such as 802.11, 802.11 with various radio information, PPP, Token Ring, FDDI, etc.
	 * 
	 * @return link layer header type
	 */
	public int getNetwork() {
		if (swap) {
			return swap32(network);
		}
		return network;
	}

	/**
	 * Create simple PCAP global header, with specified link-layer type,
	 * from existing instance of {@link PcapGlobalHeader} object.
	 * 
	 * @param linkLayerType	-	one of {@link LinkLayerType#LINKTYPE_ETHERNET}, {@link LinkLayerType#LINKTYPE_LINUX_SLL}, etc.
	 * 
	 * @return	raw byte array representing global PCAP header of 24 bytes
	 */
	public byte[] toByteArray(int linkLayerType) {
		
		final byte[] globalHeader = new byte[24]; // Always 24 bytes long PCAP header.
		final ByteBuffer buf = ByteBuffer.wrap(globalHeader);
		
		buf.putInt(this.magic);
		buf.putInt(this.version);
		buf.putInt(this.thiszone); // Zone
		buf.putInt(this.sigfigs); // SigFigs
		buf.putInt(this.snaplen); // SnapLen
		
		if (this.swap == true) {
		
			buf.putInt(swap32(linkLayerType)); // Link-Layer Type
		}
		else {
			
			buf.putInt(linkLayerType); // Link-Layer Type in BIG-ENDIAN byte order.
		}
		
		return globalHeader;
	}
	
	/**
	 * Create simple PCAP global header.
	 * 
	 * @param	magic		-	magic value, use {@link #MAGIC} or {@link #MAGIC_SWAPPED}
	 * @param	zone		-	time zone according to GMT, usually 0
	 * @param	sigfigs		-	time stamp precision, usually 0
	 * @param	snaplen		-	max. length of captured packet, usually {@link Short#MAX_VALUE}
	 * 	
	 * @param	linkLayerType	-	one of {@link LinkLayerType#LINKTYPE_ETHERNET}, {@link LinkLayerType#LINKTYPE_LINUX_SLL}, etc.
	 * 
	 * @return	raw byte array representing global PCAP header of 24 bytes
	 */
	public static byte[] toByteArray(final int magic
			, final int zone, final int sigfigs, final int snaplen, final int linkLayerType) {
		
		final byte[] globalHeader = new byte[24]; // Always 24 bytes long PCAP header.
		final ByteBuffer buf = ByteBuffer.wrap(globalHeader);

		boolean swapped = (magic == MAGIC_SWAPPED);
		
		// Magic value is 0xa1 b2 c3 d4 (in BIG ENDIAN byte order), 
		//  or swapped in LITTLE ENDIAN byte order.
		buf.putInt(magic);
		
		// Version value is major.minor format, where major is value 2 and minor is value 4,
		//  thus forming version string '2.4' for PCAP header as 'standard' among tools like Wireshark.
		if (swapped == true) {
		
			buf.putInt(VERSION_SWAPPED);
		}
		else {
			
			buf.putInt(VERSION);
		}
		
		// Zone value is time zone measured from GMT. Typically left to value 0. 
		if (swapped == true) {
			
			buf.putInt(swap32(zone)); // Zone
		}
		else {
			
			buf.putInt(zone);
		}
		
		// Accuracy of time stamps. Usually 0.
		if (swapped == true) {

			buf.putInt(swap32(sigfigs));
		} else {
			
			buf.putInt(sigfigs); // SigFigs
		}
		
		// Length of captured packets. Packets in capture file might be limited in length.
		if (swapped == true) {

			buf.putInt(swap32(snaplen));
		}
		else {
		
			buf.putInt(snaplen); // SnapLen
		}
		
		// Link layer type of 1 is for ethernet captured frames, for Linux cooked it's value is 113, etc.
		if (swapped == true) {
		
			buf.putInt(swap32(linkLayerType)); // Link-Layer Type
		}
		else {
			
			buf.putInt(linkLayerType); // Link-Layer Type in BIG-ENDIAN byte order.
		}
		
		return globalHeader;
	}
}
