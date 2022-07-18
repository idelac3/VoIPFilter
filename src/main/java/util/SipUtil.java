package util;

import rtp.RtpPacket;

/**
 * Methods to read headers and tags from SIP message are public available to other packages
 * as well.<br>
 * <br>
 * Support for compact SIP headers added according to:
 * <br> 
 *  <a href="http://www.cs.columbia.edu/sip/compact.html">SIP Compact Headers</a>
 * <br>
 * Please use methods like {@link #getCallID(String)} instead of 
 *  generic {@link #getHeaderValue(String, String)} if you expect compact SIP headers.
 *   
 *
 */
public class SipUtil {
	
	/**
	 * SIP line terminator sequence.
	 */
	final public static String CRLF = "\r\n";
	
	/**
	 * Obtain header value from SIP message.
	 * 
	 * @param message	-	SIP message as arrived on socket
	 * @param header	-	put here header name like 'To', 'From', 'Call-ID' or any you need to get value extracted, don't put 'From: '
	 * 
	 * @return extracted header value, or empty string if not found
	 */
	public static String getHeaderValue(final String message, final String header) {
		
		int start = message.indexOf(CRLF + header + ": ");
		
		if (start > 0) {
			
			// Move at begining of value.
			start = message.indexOf(' ', start) + 1;
			
			// Find end of line.
			int end = message.indexOf(CRLF, start);
			
			if (end == -1) {
			
				return "";
			}
			
			return message.substring(start, end);
		}
		else {
			
			return "";
		}
	}
	
	/**
	 * Extract first line of SIP message.
	 * 
	 * @param message	-	SIP message
	 * 
	 * @return	first line, or empty string if message is corrupted
	 */
	public static String getFirstLine(final String message) {
	
		final int end = message.indexOf(CRLF);
		
		if (end == -1) {
			
			return "";
		}
		
		return message.substring(0, end);
	}
	
	/**
	 * A handy method to extract Call-ID value from SIP message.
	 * 
	 * Every SIP message should have Call-ID header with value.
	 * 
	 * @param message	-	SIP message
	 * 
	 * @return	Call-ID value or empty string if message is corrupted
	 */
	public static String getCallID(final String message) {
		
		final String value1 = getHeaderValue(message, "Call-ID");
		final String value2 = getHeaderValue(message, "i");
		
		return value1.isEmpty() ? value2 : value1;
	}
	
	/**
	 * A handy method to extract From header value.
	 * 
	 * Every SIP message should have From header with value.
	 * 
	 * @param message	-	SIP message
	 * 
	 * @return	From value or empty string if message is corrupted
	 */
	public static String getFrom(final String message) {
		
		final String value1 = getHeaderValue(message, "From");
		final String value2 = getHeaderValue(message, "f");
		
		return value1.isEmpty() ? value2 : value1;
	}
	
	/**
	 * A handy method to extract To header value.
	 * 
	 * Every SIP message should have To header with value.
	 * 
	 * @param message	-	SIP message
	 * 
	 * @return	To value or empty string if message is corrupted
	 */
	public static String getTo(final String message) {
		
		final String value1 = getHeaderValue(message, "To");
		final String value2 = getHeaderValue(message, "t");
		
		return value1.isEmpty() ? value2 : value1;
	}
	
	/**
	 * A handy method to extract CSeq header value.
	 * 
	 * @param message	-	SIP message
	 * 
	 * @return	CSeq value or empty string if message does not contain CSeq
	 */
	public static String getCSeq(final String message) {
		
		final String value1 = getHeaderValue(message, "CSeq");
		
		return value1;
	}
	
	/**
	 * A handy method to extract Supported header value.
	 * 
	 * @param message	-	SIP message
	 * 
	 * @return	Supported value or empty string if message does not contain Supported header
	 */
	public static String getSupported(final String message) {
		
		final String value1 = getHeaderValue(message, "Supported");
		final String value2 = getHeaderValue(message, "k");
		
		return value1.isEmpty() ? value2 : value1;
	}
	
	/**
	 * A handy method to extract Contact header value.
	 * 
	 * @param message	-	SIP message
	 * 
	 * @return	Contact value or empty string if message does not contain Contact header
	 */
	public static String getContact(final String message) {
		
		final String value1 = getHeaderValue(message, "Contact");
		final String value2 = getHeaderValue(message, "m");
		
		return value1.isEmpty() ? value2 : value1;
	}
	
	/**
	 * A handy method to extract Via header value.
	 * 
	 * Every SIP message should have Via header with value.
	 * 
	 * @param message	-	SIP message
	 * 
	 * @return	Via value or empty string if message is corrupted
	 */
	public static String getVia(final String message) {
		
		final String value1 = getHeaderValue(message, "Via");
		final String value2 = getHeaderValue(message, "v");
		
		return value1.isEmpty() ? value2 : value1;
	}
	
	/**
	 * A handy method to extract 'Expires: ' header value, or 'expires=' tag value.
	 * 
	 * SIP REGISTER message should have Expires header or tag value set.
	 * 
	 * @param message	-	SIP message
	 * 
	 * @return	Expires header value or empty string if message does not contain information
	 */
	public static String getExpires(final String message) {
		
		final String value1 = getHeaderValue(message, "Expires");
		
		if (value1.isEmpty()) {
			
			int start = message.indexOf("expires=");
			
			if (start == -1) {
				
				return "";
			}
			
			start = start + "expires=".length();
			
			int end = start;
			
			while ( message.charAt(end) >= '0' && message.charAt(end) <= '9') {
				
				end++;
				
				if ( message.charAt(end) < '0' || message.charAt(end) > '9') {
					
					break;
				}
			}
				
			if (end > start) {
					
				return message.substring(start, end);
			}
			
			return "";
		}
		
		return value1;
	}
	
	/**
	 * A handy method to extract Content-Type header value.
	 * 
	 * Every SIP message with SDP body should have Content-Type header with value.
	 * 
	 * @param message	-	SIP message
	 * 
	 * @return	Content-Type value or empty string if message does not contain SDP part
	 */
	public static String getContentType(final String message) {
		
		final String value1 = getHeaderValue(message, "Content-Type");
		final String value2 = getHeaderValue(message, "c");
		
		return value1.isEmpty() ? value2 : value1;
	}

	/**
	 * A handy method to extract Content-Length header value.
	 * 
	 * Every SIP message with SDP body should have Content-Length header with value.
	 * 
	 * @param message	-	SIP message
	 * 
	 * @return	Content-Length value or empty string if message does not contain SDP part
	 */
	public static String getContentLength(final String message) {
		
		final String value1 = getHeaderValue(message, "Content-Length");
		final String value2 = getHeaderValue(message, "l");
		
		return value1.isEmpty() ? value2 : value1;
	}
	
	/**
	 * Extract from header tag value. Eg.
	 * <pre>
	 *  Via: SIP/2.0/UDP 10.250.100.45:5060;branch=z9hG4bK245d578cb2b34
	 * </pre>
	 * Via header contains tag named <i>branch</i> and to extract branch value, use this method.
	 * 
	 * @param header	-	header name, eg. Via, From, To, etc.
	 * @param tag	-	name of tag in header, eg. branch, tag, etc.
	 * 
	 * @return	tag value or empty string if header is empty or tag is not found
	 */
	public static String getTagValue(final String header, final String tag) {
				
		if (header != null && header.length() > 0) {
		
			int start = header.indexOf(tag + "=");
			
			if (start > 0) {

				// Calculate tag name and set proper index where tag value starts.
				start = start + (tag + "=").length();
				
				int end1 = header.indexOf(';', start);
				int end2 = header.indexOf('>', start);
				
				int end = header.length();
				
				if (end1 == -1 && end2 == -1) {
					
					end = header.length();
				}
				else {
					
					if (end1 == -1) {
						
						end = end2;
					}
					
					if (end2 == -1) {
						
						end= end1;
					}
					
					if (end1 < end2) {
						
						end = end1;
					}
					
					if (end2 < end1) {
						
						end = end2;
					}
				}
				
				if (start < header.length()) {

					final String tagValue = header.substring(start, end);				
					
					return tagValue;
				}
			}
		}
		
		// In all other cases return empty string signaling that extraction of tag value failed.
		return "";
	}
	
	/**
	 * Extract address (URL) part from headers like From and To. Eg.
	 * <pre>
	 *  To: <sip:6789@10.7.22.51>
	 * </pre>
	 * Method will return header value defined in sip: part.
	 * In this example it would be '6789@10.7.22.51' value. 
	 * 
	 * @param header	-	header name, eg. Via, From, To, etc.
	 * 
	 * @return	tag value or empty string if header is empty or tag is not found
	 */
	public static String getAddressValue(final String header) {
				
		if (header != null && header.length() > 0) {
		
			int start = header.indexOf("<sip:");
			int end = header.indexOf(">", start);
			
			if (start >= 0 && end > 0
					&& start < end) {

				start = start + ("<sip:").length();
				
				return header.substring(start, end);
			}
		}
		
		// In all other cases return empty string signaling that extraction of address value failed.
		return "";
	}
		
	/**
	 * Obtain from SDP part of SIP message media address, where to send RTP packets.
	 * 
	 * @param message	-	SIP message, SIP request or answer message with SDP part
	 * 
	 * @return	IP address or empty string if message has no SDP
	 */
	public static String getMediaAddress(final String message) {
		
		String remoteIP = "";
		
		final String contentType   = getContentType(message);
		final String contentLength = getContentLength(message);
		
		if (contentType.equals("application/sdp") && contentLength.length() > 0) {
			
			// Just get here SDP part of SIP message.
			final String sdp = message.substring(message.indexOf(CRLF + CRLF + "v=0") + 4);
			
			for (final String line : sdp.split(CRLF)) {
				
				if (line.startsWith("c=IN")) {
					// Here is media IP value.
					remoteIP = line.substring(line.lastIndexOf(' ') + 1);
				}
			}
		}
		
		return remoteIP;
	}
	
	/**
	 * Obtain from SDP part of SIP message media port, where to send RTP packets.
	 * 
	 * @param message	-	SIP message, SIP request or answer message with SDP part
	 * 
	 * @return	UDP port or empty string if message has no SDP
	 */
	public static String getMediaPort(final String message) {
		
		String remotePort = "";
		
		final String contentType   = getContentType(message);
		final String contentLength = getContentLength(message);
		
		if (contentType.equals("application/sdp") && contentLength.length() > 0) {	
			
			// Just get here SDP part of SIP message.
			final String sdp = message.substring(message.indexOf(CRLF + CRLF + "v=0") + 4);
			
			for (final String line : sdp.split(CRLF)) {
				
				if (line.startsWith("m=audio")) {
					// Here is media port value.
					int start = line.indexOf(' ') + 1;
					int end = line.indexOf(' ', start);
					
					remotePort = line.substring(start, end);
				}
			}
		}
		
		return remotePort;
	}
	
	/**
	 * Obtain from SDP part of SIP message one of supported media codecs (G.729, G.711 u-Law or A-Law).
	 * That will define how to encode RTP packets.
	 * 
	 * By default, G.729 has higher priority than G.711 u-Law or A-Law.
	 * 
	 * @param message	-	SIP message, SIP request or answer message with SDP part
	 * 
	 * @return	one of the following values: {@link RtpPacket#PT_G729}, {@link RtpPacket#PT_PCMA} or {@link RtpPacket#PT_PCMU}
	 */
	public static byte getMediaCodec(final String message) {
		
		final String contentType   = getContentType(message);
		final String contentLength = getContentLength(message);
		
		if (contentType.equals("application/sdp") && contentLength.length() > 0) {
			
			// Just get here SDP part of SIP message.
			final String sdp = message.substring(message.indexOf(CRLF + CRLF + "v=0") + 4);
			
			for (final String line : sdp.split(CRLF)) {
				
				if (line.startsWith("a=rtpmap")) {
					
					//
					// Priority is G.729, then G.711 A-Law, u-Law and finally SPEEX.
					//
					
					if (line.contains("g729") || line.contains("G729")) {
						
						return RtpPacket.PT_G729;
					}
					
					if (line.contains("pcma") || line.contains("PCMA")) {
						
						return RtpPacket.PT_PCMA;
					}
					
					if (line.contains("pcmu") || line.contains("PCMU")) {
						
						return RtpPacket.PT_PCMU;
					}
					
					if (line.contains("speex") || line.contains("SPEEX")) {
						
						return RtpPacket.PT_SPEEX_8000;
					}
					
				}
			}
		}

		return RtpPacket.PT_PCMU; // Fallback to G.711 u-Law here.
	}
	
}
