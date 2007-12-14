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
	private String params;

	/**
	 * Create a new instance
	 * @param params unused
	 */
	public HeloCheck(String params) {
		name = "HeloCheck " + instCounter.getAndIncrement();
		this.params = params;
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
		return new HeloCheck(params);
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
	public boolean reconfigure(String param) {
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
			// make sure, that the remote client does not HLO with a loopback addr
			if (a != null && clientAddress != null && !clientAddress.isLoopbackAddress()) {
				for (int i=a.length-1; i >= 0; i--) {
					if (a[i].isLoopbackAddress()) {
						a = null;
						break;
					}
				}
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
						log.warn(name + ": HELO " + domain 
							+ " does not match client " 
							+ clientAddress.getHostAddress());
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
	 * @param args	
	 */
	public static void main(String[] args) {
		HeloCheck h = new HeloCheck(null);
		log.info(h.doHelo("localhost").toString());
	}
}
