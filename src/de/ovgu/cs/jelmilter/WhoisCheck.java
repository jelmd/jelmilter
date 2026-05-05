/**
 * Copyright (c) 2005-2007 Jens Elkner.
 * All Rights Reserved.
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package de.ovgu.cs.jelmilter;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.mail.BodyPart;
import jakarta.mail.Header;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.ContentType;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.ovgu.cs.jelmilter.misc.ContentTypeMatcher;
import de.ovgu.cs.jelmilter.misc.MboxReader;
import de.ovgu.cs.milter4j.MailFilter;
import de.ovgu.cs.milter4j.cmd.Type;
import de.ovgu.cs.milter4j.reply.AcceptPacket;
import de.ovgu.cs.milter4j.reply.Packet;
import de.ovgu.cs.milter4j.reply.ReplyPacket;
import de.ovgu.cs.milter4j.util.Mail;
import de.ovgu.cs.milter4j.util.Misc;


/**
 * Extract URLs and check the related whois records using a whois-spam server.
 * @author 	Jens Elkner
 * @version	$Revision$
 */
public class WhoisCheck
	extends MailFilter
{
	private static final Logger log = LoggerFactory
		.getLogger(WhoisCheck.class);
	private InetSocketAddress[] addr;
	private static final AtomicInteger instCounter = new AtomicInteger();
	private String name;
	private Pattern[] patterns;
	private HashSet<String> rcptWhitelist;
	private HashSet<String> fromWhitelist;
	private long[] timeoutMap;
	/* as long as it is false, the filter tries to connect a [fallback]server
	 * 'til a serverTimeout has been reached or a servers in the list have been 
	 * tried.
	 */
	private boolean stopWaiting;
	// spam is usually <= 50KiB
	private int maxSize = 50 * 1024;

	/**
	 * Create a new Instance.
	 * @param params	a {@code ;} separated list of key=value pairs.
	 * @see #P_SERVER
	 * @see #P_PATTERN
	 * @see #P_MAXSIZE
	 * @see #P_SKIP4
	 */
	public WhoisCheck(String params) {
		if (params == null) {
			throw new IllegalArgumentException("whois-spam server address and port required");
		}
		name = "WhoisCheck " + instCounter.getAndIncrement();
		reconfigure(params, true);
	}

	/**
	 * Create a new Instance.
	 * @param addr	the socket of the whois-spam to use
	 * @param patterns	a list of hostname patterns, which are considered to be 
	 * 		spam hosts
	 * @param rcptWL	an optional set of recipient addresses, for whome this
	 * 	filter should be ignored.
	 * @param fromWL	an optional set of from addresses, for whome this
	 * 	filter should be ignored.
	 */
	public WhoisCheck(InetSocketAddress[] addr, Pattern[] patterns, 
		HashSet<String> rcptWL, HashSet<String> fromWL) 
	{
		if (addr == null) {
			throw new IllegalArgumentException("Invalid address/port");
		}
		name = "WhoisCheck " + instCounter.getAndIncrement();
		this.addr = addr;
		this.patterns = patterns;
		this.rcptWhitelist = rcptWL;
		this.fromWhitelist = fromWL;
		timeoutMap = new long[addr.length];
		stopWaiting = false;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doAbort() {
		stopWaiting = true;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doQuit() {
		stopWaiting = true;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public MailFilter getInstance() {
		return new WhoisCheck(addr, patterns, rcptWhitelist, fromWhitelist);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return name;
	}

	/** The prefix to use to specify the whois server to use. Value has the
	 * format servername:port, e.g.: server=main.do:1234. Can be specified 
	 * multiple times. In this case order is important, and the filter starts
	 * asking the 2nd server, if the first one is unavailable and so on.
	 */
	public static String P_SERVER = "server=";
	/** The prefix to use to specify a pattern, which should applied against the 
	 * FQDN of each URL found in a mail. On match, mail gets rejected. Multiple
	 * patterns can be supplied. 
	 */
	public static String P_PATTERN = "pattern=";
	/** The prefix to use to specifiy a comma separated list of recipients, for
	 * whome this filter should skipped, i.e. do nothing. See macro "{rcpt_addr}".
	 */
	public static String P_SKIP4 = "skip4=";
	
	/** The prefix to use to specifiy a comma separated list of sender addresses,
	 *  for which this filter should skipped, i.e. do nothing. See macro 
	 *  "{mail_addr}". If an address starts with ^ a startsWith() check is made,
	 *  if an address starts with $, a endsWith() match gets made, otherwise an 
	 *  equals() check is made.
	 */
	public static String P_SKIPFROM = "skipFrom=";
	/**
	 * The prefix to use to specify the max. size of a mail, which should be 
	 * scanned. I.e. if a mail is greater than the given amount, this filter 
	 * does nothing. If the given value is &lt; 0, every mail gets scanned, no
	 * matter what its size actually is. Default is 50K.
	 */
	public static String P_MAXSIZE = "maxsize=";

	private static final void warnParam(String name, String value) {
		log.warn("Invalid value \"{}\" for parameter {} ignored", value, name);
	}

	/**
	 * @see WhoisCheck#WhoisCheck(String)
	 */
	private boolean reconfigure(String params, boolean throwEx) {
		String msg = "whois-spam server (server=hostname:port) parameter required";
		if (params == null) {
			if (throwEx)
				throw new IllegalArgumentException(msg);
			log.warn(msg);
			return false;
		}
		String[] args = params.split(";");
		ArrayList<InetSocketAddress> ia = new ArrayList<InetSocketAddress>();
		ArrayList<Pattern> pl = new ArrayList<Pattern>();
		HashSet<String> skipToList = new HashSet<String>();
		HashSet<String> skipFromList = new HashSet<String>();
		for (int i=0; i < args.length; i++) {
			String param = args[i].trim();
			if (param.isEmpty()) {
				continue;
			}
			if (param.startsWith(P_SERVER)) {
				String tmp = param.substring(P_SERVER.length());
				int idx = tmp.indexOf(':');
				if (idx == -1) {
					log.warn(msg);
					continue;
				}
				String host = tmp.substring(0, idx);
				tmp = tmp.substring(idx+1);
				int aPort = -1;
				InetSocketAddress aAddr = null;
				try {
					aPort = Integer.parseInt(tmp, 10);
					aAddr = new InetSocketAddress(host, aPort);
				} catch (Exception e) {
					warnParam(P_SERVER + " (port)", tmp);
					continue;
				}
				if (aAddr.isUnresolved()) {
					warnParam(P_SERVER + " (host/ip)", tmp);
				} else {
					log.info("Configured whois-spam server " + host + ":" + aPort);
					ia.add(aAddr);
				}
			} else if (param.startsWith(P_PATTERN)) {
				String tmp = param.substring(P_PATTERN.length());
				if (tmp.isEmpty()) {
					warnParam(P_PATTERN, "");
					continue;
				}
				try {
					Pattern p = Pattern.compile(tmp);
					pl.add(p);
				} catch (Exception e) {
					log.warn(e.getLocalizedMessage());
				}
			} else if (param.startsWith(P_SKIP4)) {
				String[] tmp = param.substring(P_SKIP4.length()).split(",");
				for (int k=tmp.length-1; k >= 0; k--) {
					String rcpt = tmp[k].trim();
					if (rcpt.length() != 0) {
						skipToList.add(rcpt);
					}
				}
			} else if (param.startsWith(P_SKIPFROM)) {
				String[] tmp = param.substring(P_SKIPFROM.length()).split(",");
				for (int k=tmp.length-1; k >= 0; k--) {
					String rcpt = tmp[k].trim();
					if (rcpt.length() != 0) {
						skipFromList.add(rcpt);
					}
				}
			} else if (param.startsWith(P_MAXSIZE)) {
				String tmp = param.substring(P_MAXSIZE.length()).trim();
				try {
					int s = Integer.parseInt(tmp, 10);
					maxSize = s < 0 ? -1 : maxSize;
				} catch (Exception e) {
					warnParam(P_MAXSIZE, tmp);
				}
			} else {
				log.warn("Unknown parameter '" + param + "' ignored");
			}
		}
		if (ia.isEmpty()) {
			if (throwEx)
				throw new IllegalArgumentException(msg);
			log.warn(msg);
			return false;
		}
		rcptWhitelist = skipToList.isEmpty() ? null : skipToList;
		fromWhitelist = skipFromList.isEmpty() ? null : skipFromList;
		patterns = pl.toArray(new Pattern[pl.size()]);
		addr = ia.toArray(new InetSocketAddress[ia.size()]);
		timeoutMap = new long[ia.size()];
		log.info("Connect timeout=" + connectTimeout/60000 
			+ ", Server timeout=" + serverTimeout/60000);
		return true;
	}
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean reconfigure(String params) {
		return reconfigure(params, false);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public EnumSet<Type> getCommands() {
		 EnumSet<Type> of = EnumSet.of(Type.BODY, Type.BODYEOB);
		 if (rcptWhitelist != null) {
			 of.add(Type.RCPT);
		 }
		 if (fromWhitelist != null) {
			 of.add(Type.MAIL);
		 }
		 return of;
	}
	
	/**
	 * Need re-assembled mails to get URLs right.
	 * @return {@code true}.
	 */
	@Override
	public boolean reassembleMail() {
		return true;
	}
	
	/** Pattern to use to extract http:// URLs */
	public static Pattern uriPattern = 
		Pattern.compile("http://[-a-zA-Z0-9/\\.]+");
	/** Pattern to use to extract pseudo URLs, i.e. starting with {@code www.}
	 * but not with http://
	 */
	public static Pattern wwwPattern = 
		Pattern.compile("(^|[^/])(www\\.[-a-zA-Z0-9/\\.]+)");
	
	/**
	 * Find URLs and URL like strings in the given target.
	 * @param s		target, where to look for URLs.
	 * @param list	where to add URLs found.
	 */
	public static void findURIs(String s, List<URI> list) {
		Matcher m = uriPattern.matcher(s);
		while (m.find()) {
			try {
				URI uri = new URI(m.group());
				String host = uri.getHost();
				if (host != null && host.indexOf('.') != -1) {
					list.add(uri);
				}
			} catch (URISyntaxException e) {
				log.warn(e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("findURIs()", e);
				}
			}
		}
		m = wwwPattern.matcher(s);
		while (m.find()) {
			try {
				String host = m.group(2);
				URI uri = new URI("http://" + host);
				list.add(uri);
			} catch (URISyntaxException e) {
				log.warn(e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("findURIs()", e);
				}
			}
		}
	}

	private boolean checkObject(Object o, ContentType contentType, 
		List<URI> uriList, HashMap<String,String> macros)
		throws MessagingException, IOException
	{
		if (o instanceof String) {
			String s = o.toString();
			findURIs(s, uriList);
			return true;
		} else if (o instanceof MimeMultipart) {
			MimeMultipart part = (MimeMultipart) o;
			int idx = part.getCount();
			for (int i=0; i < idx; i++) {
				BodyPart bp = part.getBodyPart(i);
				if (!checkObject(bp.getContent(), bp.getContentTypeObj(), 
					uriList, macros)) 
				{
					return false;
				}
			}
			return true;
		} else if (o instanceof InputStream) {
			String ext = contentType == null ? "" : contentType.getSubType();
			if ((contentType != null && contentType.getPrimaryType().equals("text"))
				|| ext.equals("partial")) 
			{
				InputStream in = (InputStream) o;
				ByteArrayOutputStream bos = new ByteArrayOutputStream(4096);
				byte[] dst = new byte[4096];
				int read = 0;
				try {
					while ((read = in.read(dst)) != -1) {
						bos.write(dst, 0, read);
					}
				} catch (IOException e) {
					log.warn(getLogInfo(macros) + e.getLocalizedMessage());
					if (log.isDebugEnabled()) {
						log.debug("checkObject()", e);
					}
				} finally {
					try { in.close(); } catch (Exception x) { /* ignore */ }
				}
				String txt = ContentTypeMatcher.convert(contentType, bos.toByteArray());
				findURIs(txt, uriList);
				return true;
			}
			if (log.isDebugEnabled()) {
				log.debug(getLogInfo(macros) + "Skipping URI search for " 
					+ ContentType.normalize(contentType));
			}
			return  true;
		} else if (o instanceof MimeMessage) {
			MimeMessage m = (MimeMessage) o;
			try {
				return checkObject(m.getContent(), m.getContentTypeObj(), 
					uriList, macros);
			} catch (Exception e) {
				log.warn(getLogInfo(macros) + e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("checkObject()", e);
				}
			}
		}
		log.warn(getLogInfo(macros) + "Unable to handle msg " 
			+ o.getClass().getSimpleName() + " " + contentType);
		return false;
	}
	
	private ByteBuffer lenBuffer = ByteBuffer.allocateDirect(4);
	private static long serverTimeout = 5 * 60 * 1000;
	private static long connectTimeout = 30 * 1000;

	private SocketChannel getChannel() {
		SocketChannel ch = null;
		for (int i=0; i < addr.length && ch == null; i++) {
			long start = System.currentTimeMillis();
			long timeout = i == 0 ? serverTimeout : (connectTimeout << 1);
			if (start - timeoutMap[i] > timeout) {
				// lets try the master for max 5 min in an intervall of 30 sec
				// prefer always the master, since slaves might be not uptodate
				while (!stopWaiting) {
					try {
						ch = SocketChannel.open();
						ch.socket().setSoTimeout(8 * 60 * 1000);
						ch.configureBlocking(true);
						ch.connect(addr[i]);
					} catch (Exception e) {
						log.warn(e.getLocalizedMessage() + " (" + addr[i] + ')');
						if (log.isDebugEnabled()) {
							log.debug("getChannel", e);
						}
						ch = null;
					}
					if (ch == null) {
						long now = System.currentTimeMillis();
						if (now - start >= timeout) {
							timeoutMap[i] = now;
							break;
						}
						try { 
							Thread.sleep(connectTimeout);
						} catch (Exception e) {
							// ignore
						}
					} else {
						break;
					}
				}
			}
		}
		return ch;
	}

	private void askWhois(StringBuilder buf) {
		SocketChannel ch = getChannel();
		if (ch == null) {
			buf.setLength(0);
			log.warn("Unable to get channel to ask for " + buf.toString());
			return;
		}
		try {
			ByteBuffer bbuf = ByteBuffer.allocateDirect(buf.length()*2);
			bbuf.putInt(buf.length());
			bbuf.put(Misc.getBytes(buf.toString()));
			bbuf.flip();
			while (bbuf.hasRemaining()) {
				ch.write(bbuf);
			}
			buf.setLength(0);
			lenBuffer.clear();
			while (lenBuffer.hasRemaining() && (ch.read(lenBuffer) != -1)) {
				// continue;
			}
			lenBuffer.flip();
			int len = lenBuffer.getInt();
			bbuf.clear();
			while ((ch.read(bbuf) != -1) && len > 0) {
				bbuf.flip();
				byte b;
				while(bbuf.hasRemaining() && (b = bbuf.get()) != 0) {
					buf.append((char) b);
				}
				bbuf.clear();
			}
		} catch (Exception e) {
			buf.setLength(0);
			log.warn(e.getLocalizedMessage());
			if (log.isDebugEnabled()) {
				log.debug("askWhois", e);
			}
		} finally {
			try { ch.close(); } catch (Exception e) { /* ignore */ }
		}
	}

	private static String getLogInfo(HashMap<String, String> macros) {
		if (macros == null) {
			return "to='' from='' via='' ";
		}
		StringBuilder buf = new StringBuilder("to='");
		String tmp = macros.get("{rcpt_addr}");
		if ( tmp != null) {
			buf.append(tmp);
		}
		buf.append("' from='");
		tmp = macros.get("{mail_addr}");
		if ( tmp != null) {
			buf.append(tmp);
		}
		buf.append("' via='");
		tmp = macros.get("_");
		if ( tmp != null) {
			buf.append(tmp);
		}
		buf.append("'  ");
		return buf.toString();
	}
	private static ReplyPacket createReplyMaleformedMsg() {
		return new ReplyPacket(554, "5.7.1", 
			"Invalid message format - strict RFC compliance required");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Packet doMailFrom(String[] from, HashMap<String, String> macros) {
		if (fromWhitelist == null) {
			return null;
		}
		/* We do not use from[0], since it may contain angel brackets or not.
		 * {mail_addr} contains the normalized address, which gets supplied by
		 * sendmail via doMacro() right before doMailFrom() gets called.
		 */
		String addr = macros.get("{mail_addr}");
		boolean accept = false;
		for (String s : fromWhitelist) {
			char c = s.charAt(0);
			if (c == '^') {
				accept = addr.startsWith(s.substring(1));
			} else if (c == '$') {
				accept = addr.endsWith(s.substring(1));
			} else {
				accept = addr.equals(s);
			}
			if (accept){
				if (log.isInfoEnabled()) {
					log.info(getLogInfo(macros) + "from whitelist '" + s + '\'');
				}
				stopWaiting = true;
				return new AcceptPacket(false);
			}
		}
		return null;
	}

	/**
	 * Check, whether a recipient of the mail is in the whitelist.
	 * @return {@code accpet} if recipient is found in the whitelist, 
	 * 	{@code null} otherwise.
	 */
	@Override
	public Packet doRecipientTo(String[] recipient, HashMap<String, String> macros)
	{
		if (rcptWhitelist == null) {
			return null;
		}
		String rcpt = macros.get("{rcpt_addr}");
		if (rcpt != null && rcptWhitelist.contains(rcpt)) {
			if (log.isInfoEnabled()) {
				log.info(getLogInfo(macros) + "rcpt whitelist " + rcpt);
			}
			stopWaiting = true;
			return new AcceptPacket(false);
		}
		return null;
	}

	/**
	 * Scan the message for URLs, collect them and submit them to the configured
	 * whois-spam server.
	 */
	@Override
	public List<Packet> doEndOfMail(List<Header> headers, 
		HashMap<String,String> macros, Mail message) 
	{
		stopWaiting = false;
		ArrayList<URI> list = null;
		boolean ok = true;
		try {
			if (message == null || maxSize <= 0 || message.getSize() > maxSize) {
				return null;
			}
			list = new ArrayList<URI>();
			ok = checkObject(message.getContent(), message.getContentTypeObj(), 
				list, macros);
		} catch (Exception e) {
			if (e instanceof IOException) {
				Throwable cause = e.getCause();
				if (cause instanceof MessagingException) {
					e = (Exception) cause;
				}
			}
			log.warn(getLogInfo(macros) + e.getLocalizedMessage());
			log.debug("doEndOfMail()", e);
			ok = false;
		}
		if (!ok) {
			ArrayList<Packet> rlist = new ArrayList<Packet>();
			rlist.add(createReplyMaleformedMsg());
			return rlist;
		}
		Packet p = null;
		HashMap<String,URI> map = new HashMap<String,URI>();
		if (list != null && list.size() > 0) {
			for (URI uri : list) {
				String host = uri.getHost();
				for (int i=patterns.length-1; i >= 0; i--) {
					if (patterns[i].matcher(host).find()) {
						p = new ReplyPacket(550, "5.7.1", 
							"Rejecting spam host");
						log.info(getLogInfo(macros) + "host pattern match: " 
							+ host);
						break;
					}
				}
				if (p == null) {
					map.put(host, uri);
				} else {
					break;
				}
			}
		}
		if (p == null && map.size() > 0) {
			StringBuilder buf = new StringBuilder();
			for (String host : map.keySet()) {
				buf.append(host).append(',');
			}
			buf.setLength(buf.length()-1);
			askWhois(buf);
			if (buf.length() > 0) {
				String res[] = buf.toString().split(";");
				for (int i=res.length-1; i >= 0; i--) {
					if (res[i].length() < 1) {
						continue;
					}
					char c = res[i].charAt(0);
					if (c == 'A' || c == 'B' || c == 'F' || c == 'M') {
						p = new ReplyPacket(550, "5.7.1", 
							"Rejecting spam [" + c + "]");
						log.info(getLogInfo(macros) + res[i]);
						break;
					} else if (c == 'T' || c == 'E' || c == 'N') {
						p = new ReplyPacket(451, "4.7.1", 
							"Rejecting spam [" + c + "]");
						log.info(getLogInfo(macros) + res[i]);
						break;
					} else if (c == 'X') {
						p = new ReplyPacket(451, "4.7.1", 
							"Domain infos currently not available [" + c + "]");
						log.info(getLogInfo(macros) + res[i]);
						break;
					}
					// whitelisted domain is not sufficient for accept since
					// might be injected/faked as well
				}
			}
		}
		if (p != null) {
			ArrayList<Packet> rlist = new ArrayList<Packet>();
			rlist.add(p);
			return rlist;
		}
		return null;
	}
	
	/**
	 * Print out usage info for {@link #main(String[])}.
	 * @param out where to print.
	 */
	public static void usage(PrintStream out) {
		String EOL = "%n";
		out.printf(
"Usage: java -cp ... WhoisCheck [key=value;]* mboxFile" + EOL + EOL +
"  key=value .. helo check configuration paramters" + EOL +
"  mboxFile .. the mbox formatted file to scan" + EOL + EOL +
"keys:" + EOL +
       " %10s .. The whois check server to ask. Format: {ip|hostname}:port" + EOL +
       " %10s .. If the given regex matches the hostname part of an URI, the" + EOL +
"                message gets rejected immediately without asking the whois" + EOL +
"                check server" + EOL +
       " %10s .. don't scan messages > than the given size in bytes" + EOL +
       " %10s .. A comma separated list of whitelist recipients (accounts)," + EOL +
       "         i.e. don't scann message sent to a recipient in the given list" + EOL +
       P_SERVER, P_PATTERN, P_MAXSIZE, P_SKIP4);
	}

	/**
	 * Read a mbox file and submit URLs found to the whois-spam server
	 * @param args	0 .. server:port,pattern,... 1 .. mbox file to read
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		if (args.length < 2) {
			usage(System.err);
			System.exit(1);
		}
		WhoisCheck checker = new WhoisCheck(args[0]);
		ArrayList<Mail> mails = MboxReader.read(new File(args[1]));
		int count = 1;
		for (Mail mail : mails) {
			List<Packet> list = checker.doEndOfMail(null, null, mail);
			if (list != null) {
				for (Packet p : list) {
					log.info("msg " + count + " :" + p.toString());
				}
			}
		}
		log.info("Done.");
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
		buf.append(";name=").append(name)
			.append(';').append(P_MAXSIZE).append(maxSize);
		for (int i=0; i < addr.length; i++) {
			buf.append(';').append(P_SERVER).append(addr[i].toString());
		}
		if (patterns.length > 0) {
			for (int i=0; i < patterns.length; i++) {
				buf.append(';').append(P_PATTERN).append(patterns[i].pattern());
			}
		}
		if (rcptWhitelist != null && rcptWhitelist.size() > 0) {
			buf.append(';').append(P_SKIP4);
			for (String rcpt : rcptWhitelist) {
				buf.append(rcpt).append(',');
			}
			buf.setLength(buf.length()-1);
		}
		buf.append(";connectTimeout=").append(connectTimeout/1000)
			.append(";serverTimeout=").append(serverTimeout/1000)
			.append(']');
		return buf.toString();
	}
}
