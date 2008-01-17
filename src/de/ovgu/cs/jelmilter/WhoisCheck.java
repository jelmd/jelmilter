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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.mail.BodyPart;
import javax.mail.Header;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.ovgu.cs.jelmilter.misc.MboxReader;
import de.ovgu.cs.milter4j.MailFilter;
import de.ovgu.cs.milter4j.cmd.Type;
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
	private long[] timeoutMap;
	private boolean stopWaiting;

	/**
	 * Create a new Instance.
	 * @param serverPortPattern	a {@code |} searated server:port list, whereby 
	 * 		<var>server</var> is the hostname or IP-Address and <var>port</var> 
	 * 		the port of the whois-spam server to ask. Optionally it might be 
	 * 		followed by a comma separated list of hostname patterns, which 
	 * 		are also considered to be spam hosts.
	 * 		<p>
	 * 		E.g. server:port|fallbackserver:port,hostnamePattern0,...
	 */
	public WhoisCheck(String serverPortPattern) {
		if (serverPortPattern == null) {
			throw new IllegalArgumentException("whois-spam server address and port required");
		}
		name = "WhoisCheck " + instCounter.getAndIncrement();
		reconfigure(serverPortPattern, true);
	}

	/**
	 * Create a new Instance.
	 * @param addr	the socket of the whois-spam to use
	 * @param patterns	a list of hostname patterns, which are considered to be 
	 * 		spam hosts
	 */
	public WhoisCheck(InetSocketAddress[] addr, Pattern[] patterns) {
		if (addr == null) {
			throw new IllegalArgumentException("Invalid address/port");
		}
		name = "WhoisCheck " + instCounter.getAndIncrement();
		this.addr = addr;
		this.patterns = patterns;
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
		return new WhoisCheck(addr, patterns);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return name;
	}

	private boolean reconfigure(String serverPortPatterns, boolean throwEx) {
		String msg = "whois-spam server:port address required";
		if (serverPortPatterns == null) {
			if (throwEx)
				throw new IllegalArgumentException(msg);
			log.warn(msg);
			return false;
		}
		String[] params = serverPortPatterns.split(",");
		String[] serverPort = params[0].split("\\|");
		ArrayList<InetSocketAddress> ia = new ArrayList<InetSocketAddress>();
		for (int i=0; i < serverPort.length; i++) {
			int idx = params[0].indexOf(':');
			if (idx == -1) {
				log.warn(msg);
				continue;
			}
			String host = params[0].substring(0, idx);
			String tmp = params[0].substring(idx+1);
			int aPort = -1;
			InetSocketAddress aAddr = null;
			try {
				aPort = Integer.parseInt(tmp, 10);
				aAddr = new InetSocketAddress(host, aPort);
			} catch (Exception e) {
				log.warn("Invalid port '" + tmp + "'");
				continue;
			}
			if (aAddr == null || aAddr.isUnresolved()) {
				log.warn("Invalid host/ip '" + tmp + "'");
			} else {
				log.info("Configured whois-spam server " + host + ":" + aPort);
				ia.add(aAddr);
			}
		}
		if (ia.isEmpty()) {
			if (throwEx)
				throw new IllegalArgumentException(msg);
			log.warn(msg);
			return false;
		}
		ArrayList<Pattern> pl = new ArrayList<Pattern>();
		if (params.length > 1) {
			for (int i=params.length-1; i > 0; i--) {
				try {
					Pattern p = Pattern.compile(params[i]);
					pl.add(p);
				} catch (Exception e) {
					log.warn(e.getLocalizedMessage());
					if (log.isDebugEnabled()) {
						log.debug("reconfigure", e);
					}
				}
			}
		}
		patterns = pl.toArray(new Pattern[pl.size()]);
		addr = ia.toArray(new InetSocketAddress[ia.size()]);
		timeoutMap = new long[ia.size()];
		return true;
	}
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean reconfigure(String serverPortPattern) {
		return reconfigure(serverPortPattern, false);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public EnumSet<Type> getCommands() {
		return EnumSet.of(Type.BODY, Type.BODYEOB);
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
					log.debug("method()", e);
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
					log.debug("method()", e);
				}
			}
		}
	}

	private String getContentTypeClean(String ct) {
		return ct.replaceAll("\\n|\\r|\\t", " ").replaceAll("  +", " ");
	}

	/**
	 * Extract the extension from the MIMEMessage content type header value. 
	 * @param contentType	the content type of the mime message
	 * @return a normalized string, which might be used as an 
	 * 		extension when dumping the mime part to a file.
	 */
	public static String getExtension(String contentType) {
		String[] tmp = contentType.split(";");
		int idx = tmp[0].lastIndexOf('/');
		char[] ext = (idx != -1) 
			? tmp[0].substring(idx+1).toCharArray()
			: tmp[0].toCharArray();
		StringBuilder buf = new StringBuilder();
		for (int i=0; i < ext.length; i++) {
			if (Character.isJavaIdentifierPart(ext[i])) {
				buf.append(ext[i]);
			} else {
				buf.append('_');
			}
		}
		return buf.toString().toLowerCase();
	}

	private boolean checkObject(Object o, String contentType, List<URI> uriList,
		HashMap<String,String> macros)
	{
		if (o instanceof String) {
			String s = o.toString();
			findURIs(s, uriList);
			return true;
		} else if (o instanceof MimeMultipart) {
			try {
				MimeMultipart part = (MimeMultipart) o;
				int idx = part.getCount();
				for (int i=0; i < idx; i++) {
					BodyPart bp = part.getBodyPart(i);
					if (!checkObject(bp.getContent(), bp.getContentType(), 
						uriList, macros)) 
					{
						return false;
					}
				}
				return true;
			} catch (Exception e) {
				log.warn(getLogInfo(macros) +  e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("method()", e);
				}
			}
		} else if (o instanceof InputStream) {
			String ext = getExtension(contentType);
			if (ext.equals("plain") || ext.equals("html") || ext.equals("xml")
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
						log.debug("method()", e);
					}
				} finally {
					try { in.close(); } catch (Exception x) { /* ignore */ }
				}
				findURIs(new String(bos.toByteArray()), uriList);
				return true;
			}
			if (log.isDebugEnabled()) {
				log.debug(getLogInfo(macros) + "Skipping URI search for " 
					+ getContentTypeClean(contentType));
			}
			return  true;
		} else if (o instanceof MimeMessage) {
			MimeMessage m = (MimeMessage) o;
			try {
				return checkObject(m.getContent(), m.getContentType(), uriList,
					macros);
			} catch (Exception e) {
				log.warn(getLogInfo(macros) + e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("method()", e);
				}
			}
		}
		log.warn(getLogInfo(macros) + "Unable to handle msg " 
			+ o.getClass().getSimpleName() + " " 
			+ getContentTypeClean(contentType));
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
						log.warn(e.getLocalizedMessage());
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
			if (ch != null) {
				try { ch.close(); } catch (Exception e) { /* ignore */ }
			}
		}
	}

	private String getLogInfo(HashMap<String, String> macros) {
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
			// spam is usually <= 25KiB
			if (message == null || message.getSize() > 50*1024) {
				return null;
			}
			list = new ArrayList<URI>();
			ok = checkObject(message.getContent(), message.getContentType(), 
				list, macros);
		} catch (IOException e) {
			log.warn(getLogInfo(macros) + e.getLocalizedMessage());
			log.debug("doEndOfMail()", e);
			ok = false;
		} catch (MessagingException e) {
			log.warn(getLogInfo(macros) + e.getLocalizedMessage());
			log.debug("doEndOfMail()", e);
			ok = false;
		}
		if (!ok) {
			ArrayList<Packet> rlist = new ArrayList<Packet>();
			Packet p = new ReplyPacket(550, "5.7.1", "e-mail format error");
			log.info(getLogInfo(macros) +  "e-mail format error");
			rlist.add(p);
			return rlist;
		}
		Packet p = null;
		HashMap<String,URI> map = new HashMap<String,URI>();
		if (list.size() > 0) {
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
	 * Read a mbox file and submit URLs found to the whois-spam server
	 * @param args	0 .. server:port,pattern,... 1 .. mbox file to read
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		if (args.length < 2) {
			log.warn("Usage: java -cp ... " 
				+ "WhoisCheck server:port,pattern,... mboxFile");
			System.exit(1);
		}
		ArrayList<Mail> mails = MboxReader.read(new File(args[1]));
		WhoisCheck checker = new WhoisCheck(args[0]);
		int count = 1;
		for (Mail mail : mails) {
			List<Packet> list = checker.doEndOfMail(null, null, mail);
			if (list != null) {
				for (Packet p : list) {
					log.info("msg " + count + " :" + p.toString());
				}
			}
		}
	}
}
