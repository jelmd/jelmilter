/**
 * $Id$ 
 * 
 * Copyright (c) 2005-2008 Jens Elkner.
 * All Rights Reserved.
 *
 * This software is the proprietary information of Jens Elkner.
 * Use is subject to license terms.
 */
package de.ovgu.cs.jelmilter.misc;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Helper for CIDR matching.
 * 
 * @author 	Jens Elkner
 * @version	$Revision$
 */
public class CIDR {
	private long[] addr;
	private long[] mask;

	/**
	 * Create a new CIDR aka IP/mask record.
	 * @param addr	the address (IP) to use as base
	 * @param mask	the mask to use. If it is &lt; 1, it is automatically set to
	 * 		32 for IPv4 and to 128 for IPv6 addresses.
	 * @throws IllegalArgumentException if the given IP address is {@code null}
	 * 		or is not supported (i.e. not a IPv4 or IPv6 address)
	 */
	public CIDR(InetAddress addr, int mask) {
		init(addr, mask);
	}
	
	/**
	 * Create a new CIDR aka IP/mask record.
	 * @param cidr	a CIDR denoted as ip/mask
	 * @throws IllegalArgumentException if the given cidr is {@code null} or
	 * 		otherwise invalid
	 */
	public CIDR(String cidr) {
		try {
			int idx = cidr.indexOf('/');
			InetAddress a = InetAddress.getByName(cidr.substring(0, idx).trim());
			int m = Integer.parseInt(cidr.substring(idx+1).trim());
			init(a, m);
		} catch (Exception e) {
			throw new IllegalArgumentException("CIDR format error for " + cidr);
		}
	}
	
	private void init(InetAddress addr, int mask) {
		if (addr == null) {
			throw new IllegalArgumentException("IP Address required");
		}
		byte[] rawIP = addr.getAddress();
		this.addr = addr2long(rawIP);
		if (mask <= 0) {
			mask = rawIP.length << 3;
		}
		mask = rawIP.length == 4 ? (12 << 3 | mask) : mask;
		if (mask > 128) {
			mask = 128;
		}
		this.mask = mask2long(mask);
		this.addr[0] &= this.mask[0];
		this.addr[1] &= this.mask[1];
	}
	
	private long[] addr2long(byte[] ip) {
		long res[] = new long[2];
		if (ip.length != 4 && ip.length != 16) {
			throw new IllegalArgumentException("IP Address with " + ip.length
				+ " bytes are not supported");
		}
		int count = 0;
		res[0] = 0;
		res[1] = 0;
		if (ip.length == 4) {
			for (int i=3; i >= 0; i--, count += 8) {
				long x = 0x0ff & ip[i];
				res[1] |= x << count;
			}
		} else {
			for (int i=15; i >= 8; i--, count += 8) {
				long x = 0x0ff & ip[i];
				res[1] |= x << count;
			}
			for (int i=7; i >= 0; i--, count++) {
				long x = 0x0ff & ip[i];
				res[0] |= x << count;
			}
		}
		return res;
	}

	private long[] mask2long(int mask) {
		long[] res = new long[2];
		if (mask > 64) {
			res[0] = ~ (long) 0;
			res[1] = (~ (long) 0) << (128-mask);
		} else {
			res[1] = 0;
			res[0] = (~ (long) 0) << (64-mask);
		}
		return res;
	}
	
	/**
	 * Check, whether the given inet address falls in the range given by this CIDR.
	 * @param addr	address to check.
	 * @return {@code true} if the given address is part of this CIDR range.
	 * @throws NullPointerException if the given ip address is {@code null}
	 * @throws IllegalArgumentException if the given IP address is neither an
	 * 		IPv4 nor an IP address
	 */
	public boolean contains(InetAddress addr) {
		long[] dst = addr2long(addr.getAddress());
		return this.addr[1] == (dst[1] & mask[1]) 
			&& this.addr[0] == (dst[0] & mask[0]);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		if (addr[0] == 0 && (addr[1] >>> 32) == 0) {
			return ((addr[1] >>> 24) & 0xff) + "."
				+ ((addr[1] >>> 16) & 0xff) + "."
				+ ((addr[1] >>> 8) & 0xff) + "."
				+ (addr[1] & 0xff) + "/" 
				+ (32 - Integer.numberOfTrailingZeros((int) mask[1] & 0xffffffff));
		}
		StringBuilder buf = new StringBuilder(43);
		buf.append(Integer.toHexString((int)(addr[0] >>> 48) & 0xffff))
			.append(':')
			.append(Integer.toHexString((int)(addr[0] >>> 32) & 0xffff))
			.append(':')
			.append(Integer.toHexString((int)(addr[0] >>> 16) & 0xffff))
			.append(':')
			.append(Integer.toHexString((int)(addr[0] & 0xffff)))
			.append(':')
			.append(Integer.toHexString((int)(addr[1] >>> 48) & 0xffff))
			.append(':')
			.append(Integer.toHexString((int)(addr[1] >>> 32) & 0xffff))
			.append(':')
			.append(Integer.toHexString((int)(addr[1] >>> 16) & 0xffff))
			.append(':')
			.append(Integer.toHexString((int)(addr[1] & 0xffff)))
			.append("/");
		if (mask[1] == 0) {
			buf.append(64 - Long.numberOfTrailingZeros(mask[0]));
		} else {
			buf.append(128 - Long.numberOfTrailingZeros(mask[1]));
		}
		return buf.toString();
	}
	
	/**
	 * Check, wether the given inet address falls into the given CIDR range.
	 * @param args	
	 * @throws UnknownHostException 
	 * @throws NumberFormatException 
	 */
	public static void main(String[] args) throws NumberFormatException, UnknownHostException {
		if (args.length < 2) {
			System.err.println("Usage: java -cp ... CIDR ip/mask ip ...");
			System.exit(1);
		}
		CIDR cidr = new CIDR(args[0]);
		for (int i=1; i < args.length; i++) {
			if (cidr.contains(InetAddress.getByName(args[i]))) {
				System.out.println(args[i] + " matches " + cidr);
			} else {
				System.out.println(args[i] + " did NOT match " + cidr);
			}
		}
	}

}
