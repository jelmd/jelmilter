/**
 * $Id$ 
 * 
 * Copyright (c) 2005-2007 Jens Elkner.
 * All Rights Reserved.
 *
 * This software is the proprietary information of Jens Elkner.
 * Use is subject to license terms.
 */
package de.ovgu.cs.jelmilter;

import java.io.PrintStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Record;

import de.ovgu.cs.jelmilter.misc.CIDR;
import de.ovgu.cs.milter4j.AddressFamily;
import de.ovgu.cs.milter4j.MailFilter;
import de.ovgu.cs.milter4j.cmd.Type;
import de.ovgu.cs.milter4j.reply.Packet;
import de.ovgu.cs.milter4j.reply.ReplyPacket;

/**
 * MailFilter which verifies the connection endpoint (mail server) against its
 * submitted [E]HLO parameters.
 * 
 * @author 	Jens Elkner
 * @version	$Revision$
 */
public class HeloCheck
	extends MailFilter
{
	private static final Logger log = LoggerFactory.getLogger(HeloCheck.class);
	private static final AtomicInteger instCounter = new AtomicInteger();
	private String name;
	
	// config stuff
	private boolean strict;
	private boolean delayCheck;
	private String[] ehloWhitelist;
	private String[] fqhnWhitelist;
	private CIDR[] ipWhitelist;
	private HashSet<String> rcptWhitelist;
	private EnumSet<Type> cmds;
	
	// state
 	private Packet reply;
	private InetAddress clientAddress;
	private String ehelo;
	private String clientFQHN;
	private String clientIP;
	private String whitelisted;
	

	/**
	 * Create a new instance.
	 * 
	 * @param params a {@code ;} separated list of key=value pairs.
	 * @see #P_STRICT
	 * @see #P_DELAY_CHECK
	 * @see #P_HELO_WL
	 * @see #P_FQHN_WL
	 * @see #P_IP_WL
	 * @see #P_SKIP
	 * 
	 */
	public HeloCheck(String params) {
		name = "HeloCheck " + instCounter.getAndIncrement();
		cmds = EnumSet.of(Type.CONNECT, Type.HELO, Type.MACRO);
		reconfigure(params);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doAbort() {
		// nothing to do
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doQuit() {
		reply = null;
		clientAddress = null;
		ehelo = null;
		clientFQHN = null;
		clientIP = null;
		whitelisted = null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public MailFilter getInstance() {
		HeloCheck hc = new HeloCheck(null);
		hc.strict = strict;
		hc.delayCheck = delayCheck;
		hc.ehloWhitelist = ehloWhitelist;
		hc.fqhnWhitelist = fqhnWhitelist;
		hc.ipWhitelist = ipWhitelist;
		hc.rcptWhitelist = rcptWhitelist;
		hc.cmds = cmds;
		return hc;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * Prefix to use to indicate strict mode. If set to {@code true} connecting 
	 * clients need to HELO with a hostname, which matches their IP-Address or 
	 * the MX host listed for this client. Otherwise the mail gets rejected.
	 * Default is {@code false}.
	 */
	public static String P_STRICT = "strict=";

	/**
	 * Prefix to use to indicate, whether the helo check should be delayed.
	 * If its value is set to {@code true} the Connect and Helo checks are done
	 * as usual, however if they yield to a reject packet, it will be only sent,
	 * if the user is not authenticated. So, if this feature is enabled,
	 * possible rejects are delayed until {@link #doRecipientTo(String[], 
	 * HashMap)} gets called and rejects are logged at info level.
	 * Default is {@code false}.
	 */
	public static String P_DELAY_CHECK = "delayCheck=";

	/**
	 * Prefix to use for domains to whitelist. Value is a comma separated 
	 * list of domains, which are compared to the helo/ehlo argument, given by 
	 * the client. If the helo argument ends with one of the given strings, the
	 * mail gets not rejected. NOTE: Since helo arguments are usually faked 
	 * names in spam mails, care should be taken if one uses this type of 
	 * whitelist, should be avoided.
	 */
	public static String P_HELO_WL = "helo=";

	/**
	 * Prefix to use for FQHNs to whitelist. Value is a comma separated 
	 * list of Fully Qualified HostNames (FQHN), which are compared to the 
	 * to the FQHN of the client. If a the FQHN of the client ends with one of 
	 * the given strings, mail gets not rejected.
	 */
	public static String P_FQHN_WL = "fqhn=";

	/**
	 * Prefix to use for IP based whitelists. Value is a comma separated list
	 * of CIDRs. If a CIDR of the list matches the client's IP address, mail
	 * gets not rejected.
	 */
	public static String P_IP_WL = "ip=";
	
	/**
	 * Prefix to use for recipients whitelists. The value is a comma separated 
	 * list of recipients, for which this check should be skipped. I.e. if a
	 * recipient matches one in the given list, mail gets not rejected. 
	 * NOTE: {@value #P_DELAY_CHECK} must be set to {@code true} to get this 
	 * whitelist honored.
	 */
	public static String P_SKIP = "skip4=";
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean reconfigure(String params) {
		ehloWhitelist = null;
		ipWhitelist = null;
		fqhnWhitelist = null;
		rcptWhitelist = null;
		strict = false;
		delayCheck = false;
		reply = null;
		String[] args = {};
		if (params != null) {
			args = params.split(";");
		}

		HashSet<String> ehloWL = new HashSet<String>();
		HashSet<String> fqhnWL = new HashSet<String>();
		ArrayList<CIDR> cidrs = new ArrayList<CIDR>();
		HashSet<String> rcptWL = new HashSet<String>();
		for (int i=args.length-1; i >= 0; i--) {
			String param = args[i].trim();
			if (param.isEmpty()) {
				continue;
			}
			if (param.startsWith(P_STRICT)) {
				strict = Boolean.parseBoolean(param.substring(P_STRICT.length()));
				if (strict) {
					log.info("Using strict mode");
				}
			} else if (param.startsWith(P_DELAY_CHECK)) {
				delayCheck = Boolean.parseBoolean(param.substring(P_DELAY_CHECK.length()));
				if (delayCheck) {
					log.info("Using delay check");
				}
			} else if (param.startsWith(P_HELO_WL)) {
				String[] tmp = param.substring(P_HELO_WL.length()).split(",");
				for (int k=0; k < tmp.length; k++) {
					String t = tmp[k].trim();
					if (t.length() != 0) {
						ehloWL.add(t);
					}
				}
			} else if (param.startsWith(P_FQHN_WL)) {
				String[] tmp = param.substring(P_FQHN_WL.length()).split(",");
				for (int k=0; k < tmp.length; k++) {
					String t = tmp[k].trim();
					if (t.length() != 0) {
						fqhnWL.add(t);
					}
				}
			} else if (param.startsWith(P_IP_WL)) {
				String[] tmp = param.substring(P_IP_WL.length()).split(",");
				for (int k=0; k < tmp.length; k++) {
					String t = tmp[k].trim();
					if (t.length() != 0) {
						try {
							CIDR cidr = new CIDR(t);
							cidrs.add(cidr);
						} catch (Exception e) {
							log.warn(e.getLocalizedMessage());
							if (log.isDebugEnabled()) {
								log.debug("reconfigure", e);
							}
						}
					}
				}
			} else if (param.startsWith(P_SKIP)) {
				String[] tmp = param.substring(P_SKIP.length()).split(",");
				for (int k=0; k < tmp.length; k++) {
					String t = tmp[k].trim();
					if (t.length() != 0) {
						rcptWL.add(t);
					}
				}
			} else {
				log.warn("Unknown parameter '" + param + "' ignored");
			}
		}
		if (ehloWL.size() > 0) {
			ehloWhitelist = ehloWL.toArray(new String[ehloWL.size()]);
		}
		if (fqhnWL.size() > 0) {
			fqhnWhitelist = fqhnWL.toArray(new String[fqhnWL.size()]);
		}
		if (cidrs.size() > 0) {
			ipWhitelist = cidrs.toArray(new CIDR[cidrs.size()]);
		}
		if (rcptWL.size() > 0) {
			rcptWhitelist = rcptWL;
		}
		if (delayCheck) {
			cmds.add(Type.RCPT);
		} else {
			if (rcptWhitelist != null && rcptWhitelist.size() > 0) {
				log.warn(P_SKIP + " parameter ignored since 'delayCheck' is not enabled");
			}
			cmds.remove(Type.RCPT);
		}
		return true;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public EnumSet<Type> getCommands() {
		return cmds;
	}
	
	private String getLogInfo(HashMap<String, String> macros) {
		StringBuilder buf = new StringBuilder("to='");
		String tmp = macros.get("{rcpt_addr}");
		if (tmp != null) {
			buf.append(tmp);
		}
		buf.append("' from='");
		tmp = macros.get("{mail_addr}");
		if (tmp != null) {
			buf.append(tmp);
		}
		buf.append("' ip='");
		if (clientIP != null) {
			buf.append(clientIP);
		} else if (clientAddress != null) {
			buf.append(clientAddress.getHostAddress());
		}
		buf.append("' fqhn='");
		if (clientFQHN != null) {
			buf.append(clientFQHN);
		} else if (clientAddress != null) {
			buf.append(clientAddress.getCanonicalHostName());
		}
		buf.append("' ehlo='");
		if (ehelo != null) {
			buf.append(ehelo);
		}
		buf.append("'  ");
		return buf.toString();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Packet doRecipientTo(String[] recipient, HashMap<String,String> macros) 
	{
		if (reply != null && macros.containsKey("{auth_authen}")) {
			if (log.isDebugEnabled()) {
				log.debug("Clearing " + reply.toString() + " for " + 
					macros.get("{auth_authen}"));
			}
			reply = null;
		}
		if (reply != null && rcptWhitelist != null /* && recipient != null*/ ) {
			String rcpt = macros.get("{rcpt_addr}");
			if (rcpt != null && rcptWhitelist.contains(rcpt)) {
				whitelisted = "rcpt whitelist " + rcpt;
				reply = null;
			}
			/**
			for (int k=recipient.length-1; k != 0; k--) {
				if (rcptWhitelist.contains(recipient[k])) {
					whitelisted = "rcpt whitelist: " + recipient;
					reply = null;
					break;
				}
			}
			**/
		}
		if (log.isInfoEnabled()) {
			if (reply != null) {
				log.info(getLogInfo(macros) + reply.toString());
			} else if (whitelisted != null) {
				log.info(getLogInfo(macros) + whitelisted);
			}
		}
		return reply;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Packet doConnect(String hostname, AddressFamily family, int port, 
		String info, HashMap<String,String> macros) 
	{
		clientIP = info;
		clientFQHN = hostname;
		clientAddress = null;
		if (family == AddressFamily.INET || family == AddressFamily.INET6) {
			try {
				clientAddress = InetAddress.getByName(info);
				if (log.isDebugEnabled()) {
					log.debug("{}: client addr = {}", hostname,
						clientAddress.toString());
				}
			} catch (UnknownHostException e) {
				// ignore;
			}
		}
		return null;
	}

	private static boolean domainIsMX(String domain, InetAddress addr) {
		// allow, that the EHLO name is an MX for the given client address
		try {
			String hname = addr.getHostName();
			Record[] res = 
				new Lookup(hname, org.xbill.DNS.Type.MX).run();
			String aname = domain + ".";
			if (res != null && res.length > 0) {
				for (int i=res.length-1; i >= 0; i--) {
					String mx = ((MXRecord) res[i]).getTarget().toString();
					if (mx.equals(aname)) {
						log.debug("MX '{}' matched '{}'", aname, hname);
						return true;
					} else {
						log.debug("MX '{}' no match for '{}'", mx, aname);
					}
				}
			} else {
				log.debug("No MX for '{}' matched '{}'", hname, aname);
			}
		} catch (Exception e) {
			// ignore
		}
		return false;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Packet doHelo(String domain, HashMap<String,String> macros) {
		ehelo = domain;
		if (ehloWhitelist != null) {
			for (int i=0; i < ehloWhitelist.length; i++) {
				if (domain.endsWith(ehloWhitelist[i])) {
					whitelisted = "helo whitelist: " + ehloWhitelist[i];
					return null;
				}
			}
		}
		if (fqhnWhitelist != null && clientFQHN != null) {
			for (int i=0; i < fqhnWhitelist.length; i++) {
				if (clientFQHN.endsWith(fqhnWhitelist[i])) {
					whitelisted = "fqhn whitelist: " + fqhnWhitelist[i];
					return null;
				}
			}
		}
		if (ipWhitelist != null && clientAddress != null) {
			for (int i=0; i < ipWhitelist.length; i++) {
				if (ipWhitelist[i].contains(clientAddress)) {
					whitelisted = "ip whitelist: " + ipWhitelist[i];
					return null;
				}
			}
		}
		if (clientFQHN.startsWith("[") || clientFQHN.startsWith("IPv6:")) {
			// client IP address is required to resolve into a FQHN
			log.debug("client IP not resolvable to FQHN");
			reply = new ReplyPacket(554, "5.7.1", "Fix reverse DNS for " 
				+ clientFQHN);
			if (delayCheck) {
				return null;
			}
			return reply;
		}
		InetAddress[] a = null;
		try {
			if (domain.startsWith("[") && domain.endsWith("]")) {
				// lt. RFC nur so erlaubt "EHLO [IP]"
				domain = domain.substring(1, domain.length()-1);
				InetAddress x = InetAddress.getByName(domain);
				domain = x.getCanonicalHostName();
			} else if (domain.startsWith("IPv6:")) {
				domain = domain.substring(5);
				InetAddress x = InetAddress.getByName(domain);
				domain = x.getCanonicalHostName();
			}
			a = InetAddress.getAllByName(domain);
			// raw IP-Addresses are not allowed
			for (int i=a.length-1; i >= 0; i--) {
				String addr = a[i].getHostAddress();
				if (domain.equals(addr)) {
					log.debug("Raw address '{}' not allowed", addr);
					a = null;
					break;
				}
			}
			// make sure, that the remote client does not HLO with a local addr
			boolean isLocalClient = clientAddress == null
				|| clientAddress.isLinkLocalAddress() 
				|| clientAddress.isLoopbackAddress()
				|| clientAddress.isSiteLocalAddress();
			if (a != null && !isLocalClient) {
				for (int i=a.length-1; i >= 0; i--) {
					if (a[i].isLoopbackAddress() || a[i].isLinkLocalAddress()
						|| a[i].isSiteLocalAddress()) 
					{
						a = null;
						break;
					}
				}
				if (a != null && (strict || domain.indexOf('.') == -1)) {
					// HLO $hostname should match client-IP
					boolean match = false;
					byte[] ca = clientAddress.getAddress();
					for (int i=a.length-1; i >= 0; i--) {
						byte[] da = a[i].getAddress();
						if (Arrays.equals(ca, da)) {
							match = true;
							break;
						}
					}
					if (!match && !domainIsMX(domain, clientAddress)) {
						reply = new ReplyPacket(554, "5.7.1", 
							"MTA is not " + domain 
							+ " - fix reverse DNS/MTA configuration");
						if (delayCheck) {
							return null;
						}
						return reply;
					}
				}
			}
		} catch (Exception e) {
			a = null;
			log.debug(e.getLocalizedMessage());
		}
		if (a == null) {
			reply = new ReplyPacket(554, "5.7.1", "Protocol violation");
			if (!delayCheck) {
				return reply;
			}
		}
		return null;
	}
	
	/**
	 * Usage information for {@link #main(String[])}.
	 * @param out where to print the info.
	 */
	public static void usage(PrintStream out) {
		String EOL = "%n";
		out.printf(
"Usage: java -cp HeloCheck [key=value;]* clientIP  helo_arg" + EOL + EOL +
"  key=value .. helo check configuration paramters" + EOL +
"  clientIP  .. the simulated IPv4 address of the client" + EOL +
"  helo_arg  .. the simulated EHLOed hostname sent by the client" + EOL + EOL +
"keys:" + EOL +
      "  %10s .. If set to 'true' reject mail if neither the EHLOed hostname" + EOL +
"                has a DNS A record with an IP of the talking client nor the" + EOL +
"                client has an DNS MX entry which is equal to the EHLOed" + EOL +
"                hostname" + EOL +
      "  %10s .. If set to 'true' postpone the final decision about mail" + EOL +
"                rejection until RCPT TO cmd gets processed. Here if the client" + EOL +
"                has authenticated itself or the recipient is part of a" + EOL +
"                whitelist (see %s) a possible reject decision gets discarded" + EOL +
      "  %10s .. a comma separated whitelist of recipients (accounts), for" + EOL +
"                which this check should be skipped" + EOL +
      "  %10s .. a comma separated whitelist of domains. If an EHLOed hostname" + EOL +
"                ends with a domain given in this whitelist, mail gets accepted" + EOL +
      "  %10s .. a comma separated whitelist of domains. If the clients fully " + EOL +
"                qualified host or domain name ends with a with a domain given" + EOL +
"                in this whitelist, mail gets accepted" + EOL +
      "  %10s .. a comma separated whitelist of IPv4 addresses (CIDRs are ok" + EOL +
"                as well). For all clients connecting with an IP from the list," + EOL +
"                mail gets accepted. This should preferred over the other" + EOL +
"                whitelist options (ehlo and fqhn)!" + EOL,
	P_STRICT, P_DELAY_CHECK, P_SKIP, P_SKIP, P_HELO_WL, P_FQHN_WL, P_IP_WL
);
	}
	
	/**
	 * @param args	{[strict:][delayCheck:][(FQHN|FQDN,)*]} clientIP helo_arg
	 * @throws UnknownHostException 
	 */
	public static void main(String[] args) throws UnknownHostException {
		if (args.length < 3) {
			usage(System.err);
			System.exit(1);
		}
		HeloCheck h = new HeloCheck(args[0]);
		InetAddress addr = InetAddress.getByName(args[1]);
		HashMap<String,String> macros = new HashMap<String,String>(0);
		h.doConnect(addr.getCanonicalHostName(), AddressFamily.INET, 61739, 
			args[1], macros);
		System.out.println("doHelo result: "
			+ h.doHelo(args[2].toString(), macros));
		if (h.delayCheck) {
			System.out.println("" + h.doRecipientTo(null, macros));
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder(getClass().getSimpleName())
			.append("[cmds=");
		for (Type t : getCommands()) {
			buf.append(t.name()).append(',');
		}
		buf.setLength(buf.length()-1);
		buf.append(";name=").append(name).append(';')
			.append(P_STRICT).append(strict ? "true" : "false").append(';')
			.append(P_DELAY_CHECK).append(delayCheck ? "true" : "false");
		if (rcptWhitelist != null && rcptWhitelist.size() > 0) {
			buf.append(';').append(P_SKIP);
			for (String rcpt : rcptWhitelist) {
				buf.append(rcpt).append(',');
			}
			buf.setLength(buf.length()-1);
		}
		if (ehloWhitelist != null && ehloWhitelist.length > 0) {
			buf.append(';').append(P_HELO_WL);
			for (String ehlo : ehloWhitelist) {
				buf.append(ehlo).append(',');
			}
			buf.setLength(buf.length()-1);
		}
		if (fqhnWhitelist != null && fqhnWhitelist.length > 0) {
			buf.append(';').append(P_FQHN_WL);
			for (String hostname : fqhnWhitelist) {
				buf.append(hostname).append(',');
			}
			buf.setLength(buf.length()-1);
		}
		if (ipWhitelist != null && ipWhitelist.length > 0) {
			buf.append(';').append(P_IP_WL);
			for (CIDR cidr: ipWhitelist) {
				buf.append(cidr).append(',');
			}
			buf.setLength(buf.length()-1);
		}
		buf.append(']');
		return buf.toString();
	}
}
