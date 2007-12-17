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
	private InetSocketAddress addr;
	private static final AtomicInteger instCounter = new AtomicInteger();
	private String name;

	/**
	 * Create a new Instance.
	 * @param serverPort	server:port, whereby <var>server</var> is the 
	 * 		hostname or IP-Address and <var>port</var> the port of the whois-spam
	 * 		server to ask.
	 */
	public WhoisCheck(String serverPort) {
		if (serverPort == null) {
			throw new IllegalArgumentException("whois-spam server address and port required");
		}
		int idx = serverPort.indexOf(':');
		if (idx == -1) {
			throw new IllegalArgumentException("whois-spam server:port address required");
		}
		String host = serverPort.substring(0, idx);
		String tmp = serverPort.substring(idx+1);
		int aPort = -1;
		try {
			aPort = Integer.parseInt(tmp, 10);
			addr = new InetSocketAddress(host, aPort);
		} catch (Exception e) {
			throw new IllegalArgumentException("Invalid port '" + tmp + "'");
		}
		if (addr == null || addr.isUnresolved()) {
			throw new IllegalArgumentException("Invalid host/ip '" + tmp + "'");
		}
		name = "WhoisCheck " + instCounter.getAndIncrement();
	}

	/**
	 * Create a new Instance.
	 * @param addr	the socket of the whois-spam to use
	 */
	public WhoisCheck(InetSocketAddress addr) {
		if (addr == null || addr.isUnresolved()) {
			throw new IllegalArgumentException("Invalid address/port");
		}
		this.addr = addr;
		name = "WhoisCheck " + instCounter.getAndIncrement();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doAbort() {
		// nothing todo
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doQuit() {
		// nothing todo
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public MailFilter getInstance() {
		return new WhoisCheck(addr);
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
	public boolean reconfigure(String serverPort) {
		if (serverPort == null) {
			log.warn("whois-spam server address and port required");
			return false;
		}
		int idx = serverPort.indexOf(':');
		if (idx == -1) {
			log.warn("whois-spam server:port address required");
			return false;
		}
		String host = serverPort.substring(0, idx);
		String tmp = serverPort.substring(idx+1);
		int aPort = 1;
		InetSocketAddress aAddr = null;
		try {
			aPort = Integer.parseInt(tmp, 10);
			aAddr = new InetSocketAddress(host, aPort);
		} catch (Exception e) {
			log.warn("Invalid port '" + tmp + "'");
			return false;
		}
		if (addr == null || addr.isUnresolved()) {
			log.warn("Invalid host/ip '" + tmp + "'");
			return false;
		}
		this.addr = aAddr;
		return true;
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
				if (uri.getHost().indexOf('.') != -1) {
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
		return buf.toString();
	}

	private void checkObject(Object o, String contentType, List<URI> uriList) {
		if (o instanceof String) {
			String s = o.toString();
			WhoisCheck.findURIs(s, uriList);
		} else if (o instanceof MimeMultipart) {
			try {
				MimeMultipart part = (MimeMultipart) o;
				int idx = part.getCount();
				for (int i=0; i < idx; i++) {
					BodyPart bp = part.getBodyPart(i);
					checkObject(bp.getContent(), bp.getContentType(), uriList);
				}
			} catch (Exception e) {
				log.warn(e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("method()", e);
				}
			}
		} else if (o instanceof InputStream) {
			String ext = WhoisCheck.getExtension(contentType);
			if (ext.equals("plain") || ext.equals("html") || ext.equals("xml")) {
				InputStream in = (InputStream) o;
				ByteArrayOutputStream bos = new ByteArrayOutputStream(4096);
				byte[] dst = new byte[4096];
				int read = 0;
				try {
					while ((read = in.read(dst)) != -1) {
						bos.write(dst, 0, read);
					}
				} catch (IOException e) {
					log.warn(e.getLocalizedMessage());
					if (log.isDebugEnabled()) {
						log.debug("method()", e);
					}
				} finally {
					try { in.close(); } catch (Exception x) { /* ignore */ }
				}
				WhoisCheck.findURIs(new String(bos.toByteArray()), uriList);
			}
		} else if (o instanceof MimeMessage) {
			MimeMessage m = (MimeMessage) o;
			try {
				checkObject(m.getContent(), m.getContentType(), uriList);
			} catch (Exception e) {
				log.warn(e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("method()", e);
				}
			}
		} else {
			log.warn("Unable to handle msg " + o.getClass().getSimpleName() 
				+ " " + contentType);
		}
	}
	
	private ByteBuffer lenBuffer = ByteBuffer.allocateDirect(4);

	private void askWhois(StringBuilder buf) {
		SocketChannel ch = null;
		try {
			ch = SocketChannel.open();
			ch.socket().setSoTimeout(5 * 60 * 1000);
			ch.configureBlocking(true);
			ch.connect(addr);
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

	/**
	 * Scan the message for URLs, collect them and submit them to the configured
	 * whois-spam server.
	 */
	@Override
	public List<Packet> doEndOfMail(List<Header> headers, 
		HashMap<String,String> macros, Mail message) 
	{
		ArrayList<URI> list = null;
		try {
			// spam is usually <= 25KiB
			if (message == null || message.getSize() > 50*1024) {
				return null;
			}
			list = new ArrayList<URI>();
			checkObject(message.getContent(), message.getContentType(), list);
		} catch (IOException e) {
			log.warn(e.getLocalizedMessage());
			if (log.isDebugEnabled()) {
				log.debug("method()", e);
			}
		} catch (MessagingException e) {
			log.warn(e.getLocalizedMessage());
			if (log.isDebugEnabled()) {
				log.debug("method()", e);
			}
		}
		if (list.size() > 0) {
			HashMap<String,URI> map = new HashMap<String,URI>();
			for (URI uri : list) {
				map.put(uri.getHost(), uri);
			}
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
					if (c == 'A' || c == 'B' || c == 'F') {
						ReplyPacket p = new ReplyPacket(550, "5.7.1", 
							"Rejecting spam [" + c + "]");
						log.info(res[i]);
						ArrayList<Packet> rlist = new ArrayList<Packet>();
						rlist.add(p);
						return rlist;
					} else if (c == 'T' || c == 'E' || c == 'N') {
						ReplyPacket p = new ReplyPacket(451, "4.7.1", 
							"Rejecting spam [" + c + "]");
						log.info(res[i]);
						ArrayList<Packet> rlist = new ArrayList<Packet>();
						rlist.add(p);
						return rlist;
					}
					// whitelisted domain is not sufficient for accept since
					// might be injected/faked as well
				}
			}
		}
		return null;
	}
	
	/**
	 * Read a mbox file and submit URLs found to the whois-spam server
	 * @param args	0 .. server:port, 1 .. mbox file to read
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		if (args.length < 2) {
			log.warn("Usage: java -cp ... WhoisCheck server:port mboxFile");
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
