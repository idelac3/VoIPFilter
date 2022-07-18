package packet;

public class LinkLayerType {

	/**
	 * BSD loopback encapsulation; the link layer header is a 4-byte field, 
	 * in host byte order, containing a value of 2 for IPv4 packets, 
	 * a value of either 24, 28, or 30 for IPv6 packets, 
	 * a value of 7 for OSI packets, or a value of 23 for IPX packets.
	 * <p> 
	 * All of the IPv6 values correspond to IPv6 packets.
	 * <p>
	 * Code reading files should check for all of them.
	 */
	public static final int LINKTYPE_NULL = 0;
	
	/**
	 * 	IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up).
	 *  The 10MB in the DLT_ name is historical.
	 */
	public static final int LINKTYPE_ETHERNET =	1;
	
	/**
	 * PPP, as per RFC 1661 and RFC 1662.
	 * If the first 2 bytes are 0xff and 0x03, it's PPP in HDLC-like framing, 
	 *  with the PPP header following those two bytes, 
	 *  otherwise it's PPP without framing, 
	 *  and the packet begins with the PPP header. 
	 * <p> 
	 * The data in the frame is not octet-stuffed or bit-stuffed.
	 */
	public static final int LINKTYPE_PPP = 9;
	
	/**
	 * Linux "cooked" capture encapsulation.
	 * <p>
	 * See
	 * <a href="http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html">Linux cooked capture encapsulation</a>
	 * for more information.
	 */
	public static final int LINKTYPE_LINUX_SLL = 113;
}
