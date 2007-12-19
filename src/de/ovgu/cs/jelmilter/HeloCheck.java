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
	private String[] whitelist;
	private String reverse;

	/**
	 * Create a new instance.
	 * If the param starts with {@code strict}, connecting clients need to
	 * HELO with a hostname, which matches their IP-Address. It might be 
	 * followed by a list of domains or hostnames, for which the helo check
	 * should be skipped (match uses *.endsWith(domain).
	 * 
	 * @param params [strict:]domain,...,domain
	 */
	public HeloCheck(String params) {
		name = "HeloCheck " + instCounter.getAndIncrement();
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
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public MailFilter getInstance() {
		HeloCheck hc = new HeloCheck(null);
		hc.strict = strict;
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
		if (params != null) {
			strict = params.startsWith("strict");
			String doms = params;
			if (strict) {
				doms = params.length() > "strict".length() +1
					? params.substring("strict".length()+1)
					: "";
			}
			String[] tmp = doms.split(",");
			ArrayList<String> hnames = new ArrayList<String>();
			for (int i=0; i < tmp.length; i++) {
				String t = tmp[i].trim();
				if (t.length() != 0) {
					hnames.add(t);
				}
			}
			whitelist = hnames.size() > 0 
				? hnames.toArray(new String[hnames.size()])
				: null;
		} else {
			whitelist = null;
			strict = false;
		}
		return true;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public EnumSet<Type> getCommands() {
		return EnumSet.of(Type.CONNECT, Type.HELO);
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
			return new ReplyPacket(554, "5.7.1", "Fix reverse DNS for " + reverse);
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
							return new ReplyPacket(554, "5.7.1", 
								"MTA is not " + domain 
								+ " - fix reverse DNS/MTA configuration");
						}
					}
				}
			}
		} catch (Exception e) {
			a = null;
			log.debug(e.getLocalizedMessage());
		}
		return a == null
			? new ReplyPacket(554, "5.7.1", "Protocol violation")
			: new ContinuePacket();
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
