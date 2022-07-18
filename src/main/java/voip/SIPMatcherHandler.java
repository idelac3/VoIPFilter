package voip;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

import packet.UdpDatagram;
import util.SipUtil;

/**
 * Matcher that will return if input UDP packet (SIP message or RTP audio),
 * matches the given criteria (filter string).
 */
class SIPMatcherHandler implements Consumer<UdpDatagram> {

	public static final int SIP_PORT = 5060;
	
	private final String filter;
	
	private boolean matched;
	
	/**
	 * Hold here found media ports, from SDP part of SIP message.
	 * Later this list is used to match also RTP packets.
	 */
	private final Set<Integer> mediaPorts;
	
	public SIPMatcherHandler(final String filter) {
	
		this.filter = filter;
		
		this.matched = false;
		
		this.mediaPorts = new HashSet<>();
	}
	
	@Override
	public void accept(final UdpDatagram udp) {
		
		if (udp.getDstPort() == SIP_PORT
				|| udp.getSrcPort() == SIP_PORT) {
			
			
			//
			// Check that input message is really SIP message.
			//
			
			final String msg = new String(udp.getPayload());
			
			final String firstLine = SipUtil.getFirstLine(msg); 
			
			if (firstLine.startsWith("SIP/2.0")
					|| firstLine.endsWith("SIP/2.0")) {
				
				// Here do matching on input string
				// that must be present in one of SIP
				// headers: To, From or Call-ID.
				this.matched = match(msg);
			}
			else {
				
				this.matched = false;
			}
		}
		else if (this.mediaPorts.contains(
				Integer.valueOf(udp.getDstPort())) == true ||
						this.mediaPorts.contains(
								Integer.valueOf(udp.getSrcPort())) == true ) {
			
			// Here we match RTP packets based on UDP port value
			// stored in media port hash-set.
			this.matched = true;
		}
		else {
			
			this.matched = false;
		}
	}
	
	private boolean match(final String message) {
		
		if (filter == null) {
		
			// If filtering is not enabled, then match all.
			return true;
		}
		
		//
		// Use SIP headers Call-ID, From, or To to match against given filter value.
		//
		
		final String callId = SipUtil.getCallID(message);
		final String from = SipUtil.getFrom(message);
		final String to = SipUtil.getTo(message);
		
		boolean match = callId.contains(filter) 
				|| from.contains(filter) 
				|| to.contains(filter);		
		
		//
		// Extract media port, UDP port which is used for RTP.
		//
		
		if (SipUtil.getContentType(message).contains("application/sdp") == true
				&& match == true) {
			
			final String mediaPort = SipUtil.getMediaPort(message);
			
			try {
				
				// Add new / overwrite existing media port value.
				this.mediaPorts.add(Integer.parseInt(mediaPort));
			}
			catch (final NumberFormatException ex) {
				
			}
		}
		
		return match;
	}
	
	/**
	 * Check if last processed UDP packet by this handler contains
	 * a SIP message that matches configured filter.
	 *  
	 * @return	true 	-	if SIP message contains value defined by filter parameter
	 */
	public boolean didMatch() {
		
		return this.matched;
	}
}
