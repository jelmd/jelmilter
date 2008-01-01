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
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Record;

import de.ovgu.cs.milter4j.AddressFamily;
import de.ovgu.cs.milter4j.MailFilter;
import de.ovgu.cs.milter4j.cmd.Type;
import de.ovgu.cs.milter4j.reply.ContinuePacket;
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
	private InetAddress clientAddress;
	private boolean strict;
	private boolean delayCheck;
	private String[] whitelist;
	private String reverse;
	private Packet reply;
	private EnumSet<Type> cmds;

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
	 * possible rejects are delayed until {@link #doMailFrom(String[])} gets
	 * called.
	 * <p>
	 * Any other argument gets interpreted as a comma separated list of domains 
	 * or hostnames, for which the helo check should be skipped (match uses 
	 * *.endsWith(domain).
	 * 
	 * @param params [strict:][delayCheck:][domain,...,domain]
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
		clientAddress = null;
		reverse = null;
		reply = null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public MailFilter getInstance() {
		HeloCheck hc = new HeloCheck(null);
		hc.strict = strict;
		hc.delayCheck = delayCheck;
		hc.whitelist = whitelist;
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
		whitelist = null;
		strict = false;
		delayCheck = false;
		reply = null;
		if (params != null) {
			String[] args = params.split(":");
			for (int i=args.length-1; i >= 0; i--) {
				if (args[i].equalsIgnoreCase("strict")) {
					strict = true;
				} else if (args[i].equalsIgnoreCase("delayCheck")) {
					delayCheck = true;
				} else {
					String[] tmp = args[i].split(",");
					ArrayList<String> hnames = new ArrayList<String>();
					for (int k=0; k < tmp.length; k++) {
						String t = tmp[k].trim();
						if (t.length() != 0) {
							hnames.add(t);
						}
					}
					whitelist = hnames.size() > 0 
						? hnames.toArray(new String[hnames.size()])
						: null;
				}
			}
		}
		if (delayCheck) {
			cmds.add(Type.MAIL);
			cmds.add(Type.MACRO);
		} else {
			cmds.remove(Type.MAIL);
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
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doMacros(HashMap<String,String> allMacros, 
		HashMap<String,String> newMacros) 
	{
		if (delayCheck && newMacros.containsKey("{auth_authen}")) {
			// this macro comes always after connect and helo checks
			reply = null;
		}
		return;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Packet doMailFrom(String[] from) {
		return reply;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Packet doConnect(String hostname, AddressFamily family, int port, 
		String info) 
	{
		if (hostname.startsWith("[") || hostname.startsWith("IPv6:")) {
			reverse = info;
			return new ContinuePacket();
		}
		reverse = null;
		clientAddress = null;
		if (family == AddressFamily.INET || family == AddressFamily.INET6) {
			try {
				clientAddress = InetAddress.getByName(info);
				log.debug("{}: client addr = {}", name, clientAddress.toString());
			} catch (UnknownHostException e) {
				// ignore;
			}
		}
		return new ContinuePacket();
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
	public Packet doHelo(String domain) {
		if (reverse != null) {
			reply = new ReplyPacket(554, "5.7.1", "Fix reverse DNS for " + reverse);
			if (delayCheck) {
				return null;
			}
			return reply;
		}
		if (whitelist != null) {
			for (int i=0; i < whitelist.length; i++) {
				if (domain.endsWith(whitelist[i])) {
					return new ContinuePacket();
				}
			}
		}
		InetAddress[] a = null;
		try {
			if (domain.startsWith("[") && domain.endsWith("]")) {
				// das beknackte thunderbird sagt EHLO [IP] - brainfuck
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
					if (a != null) {
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
	 * @param args	none
	 * @throws UnknownHostException 
	 */
	public static void main(String[] args) throws UnknownHostException {
		if (args.length < 3) {
			System.err.println("Usage: java -cp HeloCheck "
				+ "{[strict][:(FQHN|FQDN,)*]} clientIP helo_arg");
			System.exit(1);
		}
		HeloCheck h = new HeloCheck(args[0]);
		InetAddress addr = InetAddress.getByName(args[1]);
		h.doConnect(addr.getCanonicalHostName(), AddressFamily.INET, 61739, 
			args[1]);
		log.info(h.doHelo(args[2]).toString());
	}
}
