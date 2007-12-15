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
		if (hostname.startsWith("[")) {
			return new ReplyPacket(554, "5.7.1", "Fix reverse DNS for " + info);
		}
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

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Packet doHelo(String domain) {
		if (whitelist != null) {
			for (int i=0; i < whitelist.length; i++) {
				if (domain.endsWith(whitelist[i])) {
					return new ContinuePacket();
				}
			}
		}
		InetAddress[] a = null;
		try {
			a = InetAddress.getAllByName(domain);
			// we do not allow IP-Address, but hostnames, only
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
						if (!match) {
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
	 */
	public static void main(String[] args) {
		HeloCheck h = new HeloCheck("strict");
		h.doConnect("p54BC8CDD.dip0.t-ipconnect.de", AddressFamily.INET,
			61739, "84.188.140.221");
		log.info(h.doHelo("strict:fred.los.de").toString());
		h = new HeloCheck("los.de");
		h.doConnect("p54BC8CDD.dip0.t-ipconnect.de", AddressFamily.INET,
			61739, "84.188.140.221");
		log.info(h.doHelo("fred.los.de").toString());
	}
}
