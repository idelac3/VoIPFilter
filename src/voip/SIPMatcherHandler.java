package voip;

import java.util.function.Consumer;

import packet.UdpDatagram;
import util.SipUtil;

class SIPMatcherHandler implements Consumer<UdpDatagram> {

	public static final int SIP_PORT = 5060;
	
	private final String filter;
	
	private boolean matched;
	
	public SIPMatcherHandler(final String filter) {
	
		this.filter = filter;
		
		this.matched = false;
	}
	
	@Override
	public void accept(final UdpDatagram udp) {
		
		if (udp.getDstPort() == SIP_PORT
				|| udp.getSrcPort() == SIP_PORT) {
			
			final String msg = new String(udp.getPayload());
			
			final String firstLine = SipUtil.getFirstLine(msg); 
			
			if (firstLine.startsWith("SIP/2.0")
					|| firstLine.endsWith("SIP/2.0")) {
				
				this.matched = match(msg);
			}
			else {
				
				this.matched = false;
			}
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
		
		return callId.contains(filter) 
				|| from.contains(filter) 
				|| to.contains(filter);
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
