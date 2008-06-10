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
	 * The argument is a list of parameters separate by a {@code :} (colon).
	 * If an argument is {@code strict}, connecting clients need to
	 * HELO with a hostname, which matches their IP-Address or the MX host
	 * listed for this client.
	 * <p>
	 * If an argument is {@code delayCheck}, the Connect and Helo checks are done
	 * as usual, however if the yield to a reject packet, it will be only sent,
	 * if the user is not authenticated. So, if this feature is enabled,
	 * possible rejects are delayed until {@link #doRecipientTo(String[], HashMap)} 
	 * gets called and rejects are logged at info level.
	 * <p>
	 * Any other argument gets interpreted as a comma separated whitelists of 
	 * domains, hostnames or IP addresses, for which the helo check should be 
	 * skipped. If the list starts with {@code ip=}, CIDRs are expected, which 
	 * are matched against the clients IP address. If the list starts with
	 * {@code fqhn=} the given Strings are compared to the client's fully 
	 * qualified hostname (FQHN) and matches, if the FQHN ends with the given 
	 * string. If the list starts with {@code helo=}, the given Strings are 
	 * compared to the helo/ehlo argument, given by the client and matches, if 
	 * the helo argument ends with the given string. NOTE: Since helo arguments
	 * are usually faked names in spam mails, care should be taken if one uses
	 * this type of whitelist.
	 * 
	 * @param params [strict:][delayCheck:][{helo|ip|fqhn}=domain,...,domain]
	 */
	public HeloCheck(String params) {
		name = "HeloCheck " + instCounter.getAndIncrement();
		cmds = EnumSet.of(Type.CONNECT, Type.HELO);
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
		if (params != null) {
			String[] args = params.split(":");
			for (int i=args.length-1; i >= 0; i--) {
				if (args[i].equalsIgnoreCase("strict")) {
					strict = true;
					log.info("Using strict mode");
				} else if (args[i].equalsIgnoreCase("delayCheck")) {
					delayCheck = true;
					log.info("Using delay check");
				} else if (args[i].length() != 0) {
					if (args[i].startsWith("helo=")) {
						String[] tmp = args[i].substring(5).split(",");
						ArrayList<String> hnames = new ArrayList<String>();
						for (int k=0; k < tmp.length; k++) {
							String t = tmp[k].trim();
							if (t.length() != 0) {
								hnames.add(t);
							}
						}
						ehloWhitelist = hnames.size() > 0 
							? hnames.toArray(new String[hnames.size()])
							: null;
					} else if (args[i].startsWith("fqhn=")) {
						String[] tmp = args[i].substring(5).split(",");
						ArrayList<String> hnames = new ArrayList<String>();
						for (int k=0; k < tmp.length; k++) {
							String t = tmp[k].trim();
							if (t.length() != 0) {
								hnames.add(t);
							}
						}
						fqhnWhitelist = hnames.size() > 0 
							? hnames.toArray(new String[hnames.size()])
							: null;
					} else if (args[i].startsWith("ip=")) {
						String[] tmp = args[i].substring(3).split(",");
						ArrayList<CIDR> cidrs = new ArrayList<CIDR>();
						for (int k=0; k < tmp.length; k++) {
							String t = tmp[k].trim();
							if (t.length() != 0) {
								CIDR cidr = null;
								try {
									cidr = new CIDR(t);
									cidrs.add(cidr);
								} catch (Exception e) {
									log.warn(e.getLocalizedMessage());
									if (log.isDebugEnabled()) {
										log.debug("reconfigure", e);
									}
								}
							}
						}
						ipWhitelist = cidrs.size() > 0 
							? cidrs.toArray(new CIDR[cidrs.size()])
							: null;
					} else if (args[i].startsWith("rcpt=")) {
						String[] tmp = args[i].substring(3).split(",");
						rcptWhitelist = new HashSet<String>();
						for (int k=tmp.length-1; k >= 0; k--) {
							String rcpt = tmp[k].trim();
							if (rcpt.length() != 0) {
								rcptWhitelist.add(rcpt.startsWith("<") ? rcpt : ("<" + rcpt + ">"));
							}
						}
						if (rcptWhitelist.isEmpty()) {
							rcptWhitelist = null;
						}
					}
				} 
			}
		}
		if (delayCheck) {
			cmds.add(Type.RCPT);
			cmds.add(Type.MACRO);
		} else {
			cmds.remove(Type.RCPT);
			cmds.remove(Type.MACRO);
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
		if (reply != null && rcptWhitelist != null && recipient != null) {
			for (int k=recipient.length-1; k != 0; k--) {
				if (rcptWhitelist.contains(recipient[k])) {
					whitelisted = "rcpt whitelist: " + recipient;
					reply = null;
					break;
				}
			}
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
				log.debug("{}: client addr = {}", name, clientAddress.toString());
			} catch (UnknownHostException e) {
				// ignore;
			}
		}
		return null;
	}

	private boolean domainIsMX(String domain, InetAddress addr) {
		// allow, that the EHLO name is an MX for the given client address
		try {
			String aname = addr.getHostName();
			Record[] res = 
				new Lookup(aname, org.xbill.DNS.Type.MX).run();
			aname = domain + ".";
			if (res != null && res.length > 0) {
				for (int i=res.length-1; i >= 0; i--) {
					String mx = ((MXRecord) res[i]).getTarget().toString();
					if (mx.equals(aname)) {
						return true;
					}
				}
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
			if (delayCheck) {
				return null;
			}
			return reply;
		}
		return null;
	}
	
	/**
	 * @param args	{[strict:][delayCheck:][(FQHN|FQDN,)*]} clientIP helo_arg
	 * @throws UnknownHostException 
	 */
	public static void main(String[] args) throws UnknownHostException {
		if (args.length < 3) {
			System.err.println("Usage: java -cp HeloCheck "
				+ "{[strict:][delayCheck:][(FQHN|FQDN,)*]} clientIP helo_arg");
			System.exit(1);
		}
		HeloCheck h = new HeloCheck(args[0]);
		InetAddress addr = InetAddress.getByName(args[1]);
		HashMap<String,String> macros = new HashMap<String,String>(0);
		h.doConnect(addr.getCanonicalHostName(), AddressFamily.INET, 61739, 
			args[1], macros);
		log.info("" + h.doHelo(args[2].toString(), macros));
		if (h.delayCheck) {
			log.info("" + h.doRecipientTo(null, macros));
		}
	}
}
