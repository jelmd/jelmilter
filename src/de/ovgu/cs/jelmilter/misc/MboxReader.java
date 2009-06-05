/**
 * $Id$ 
 * 
 * Copyright (c) 2005-2007 Jens Elkner.
 * All Rights Reserved.
 *
 * This software is the proprietary information of Jens Elkner.
 * Use is subject to license terms.
 */
package de.ovgu.cs.jelmilter.misc;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.Map.Entry;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.SharedByteArrayInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.ovgu.cs.jelmilter.WhoisCheck;
import de.ovgu.cs.milter4j.util.Mail;
import de.ovgu.cs.whois.Whois;

/**
 * Utility for testing/extraction
 * 
 * @author 	Jens Elkner
 * @version	$Revision$
 */
public class MboxReader {
	private static final Logger log = LoggerFactory
		.getLogger(MboxReader.class);

	/**
	 * Empty init.
	 */
	public MboxReader() {
		// later
	}
	
	/**
	 * Read an mbox file.
	 * <p>
	 * NOTE: Maps the whole file to memory and uses 
	 * {@link SharedByteArrayInputStream} to work on it.
	 * 
	 * @param mbox		mbox file to read
	 * @return	a possible empty list
	 * @throws IOException
	 */
	public static ArrayList<Mail> read(File mbox) throws IOException {
		ArrayList<Mail> msg = new ArrayList<Mail>();
		if (mbox == null) {
			log.info("No mbox file to read - nothing to do");
			return msg;
		}
		byte[] src = new byte[(int) mbox.length()];
		int count = 0;
		int i = 0;
		FileInputStream ir = null;
		try {
			ir = new FileInputStream(mbox);
			while ((i = ir.read(src, count, src.length - count)) != -1
				&& count < src.length) 
			{
				count += i;
			}
		} finally {
			if (ir != null) {
				try { ir.close(); } catch (Exception x) { /* ignore */ }
			}
		}
		byte[] from = new byte[] { '\n', 'F', 'r', 'o', 'm', ' '};
		int eol = 0;
		while (src[eol] != '\n') {
			eol++;
		}
		for (i=eol+1; i + from.length < src.length; i++) {
			for (int k=from.length-1; k >= 0; k--) {
				if (src[i+k] != from[k]) {
					break;
				}
				if (k==0) {
					// start of a new message
					SharedByteArrayInputStream in = 
						new SharedByteArrayInputStream(src, eol+1, i - eol -1);
					try {
						Mail m = new Mail(in);
						msg.add(m);
					} catch (MessagingException e) {
						log.warn(e.getLocalizedMessage());
						if (log.isDebugEnabled()) {
							log.debug("method()", e);
						}
					}
					eol = i+from.length;
					while (src[eol] != '\n') {
						eol++;
					}
					i = eol;
				}
			}
		}
		SharedByteArrayInputStream in = 
			new SharedByteArrayInputStream(src, eol+1, src.length - eol -1);
		try {
			Mail m = new Mail(in);
			msg.add(m);
		} catch (MessagingException e) {
			log.warn(e.getLocalizedMessage());
			if (log.isDebugEnabled()) {
				log.debug("method()", e);
			}
		}
		log.info("found " + msg.size() + " messages");
		return msg;
	}
	
	private void dump(File file, byte[] content) {
		FileOutputStream fos = null; 
		try {
			fos = new FileOutputStream(file);
			fos.write(content);
		} catch (IOException e) {
			log.warn(e.getLocalizedMessage());
			if (log.isDebugEnabled()) {
				log.debug("method()", e);
			}
		} finally {
			if (fos != null) {
				try { fos.close(); } catch (Exception e) { /* ignore */ }
			}
		}
	}
	
	private void dumpObject(File dir, String prefix, int count, Object o,
		String contentType, List<URI> uriList) 
	{
		log.info(contentType);
		if (o instanceof String) {
			String s = o.toString();
			dump(new File(dir, prefix + ".txt"), s.getBytes());
			WhoisCheck.findURIs(s, uriList);
		} else if (o instanceof MimeMultipart) {
			try {
				MimeMultipart part = (MimeMultipart) o;
				int idx = part.getCount();
				for (int i=0; i < idx; i++) {
					BodyPart bp = part.getBodyPart(i);
					dumpObject(dir, prefix + "." + i, count, bp.getContent(), 
						bp.getContentType(), uriList);
				}
			} catch (Exception e) {
				log.warn("msg " + count + " - " + e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("method()", e);
				}
			}
		} else if (o instanceof InputStream) {
			InputStream in = (InputStream) o;
			ByteArrayOutputStream bos = new ByteArrayOutputStream(4096);
			byte[] dst = new byte[4096];
			int read = 0;
			try {
				while ((read = in.read(dst)) != -1) {
					bos.write(dst, 0, read);
				}
			} catch (IOException e) {
				log.warn("msg " + count + " - " + e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("method()", e);
				}
			} finally {
				try { in.close(); } catch (Exception x) { /* ignore */ }
			}
			String ext = WhoisCheck.getExtension(contentType);
			if (ext.equals("plain") || ext.equals("html") || ext.equals("xml")) {
				WhoisCheck.findURIs(new String(bos.toByteArray()), uriList);
			}
			dump(new File(dir, prefix + "." + ext), bos.toByteArray());
		} else if (o instanceof MimeMessage) {
			MimeMessage m = (MimeMessage) o;
			try {
				dumpObject(dir, prefix, count, m.getContent(), 
					m.getContentType(), uriList);
			} catch (Exception e) {
				log.warn("msg " + count + " - " + e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("method()", e);
				}
			}
		} else {
			log.warn("Unable to handle msg " + count + " " 
				+ o.getClass().getSimpleName() + " " + contentType);
		}
	}

	/**
	 * Dump all message parts to the given directory prefixed with the number 
	 * of message in mailbox order.
	 * @param dir		base directory for storage
	 * @param mails		mails to dump
	 * @param uriList	if URLs are found in text parts of the mails, add them 
	 * 		to this list
	 */
	public void dump(File dir, ArrayList<Mail> mails, List<URI> uriList) {
		if (!dir.exists()) {
			if (!dir.mkdir()) {
				log.warn("Unable to create " + dir);
				return;
			}
		}
		if (!dir.isDirectory()) {
			log.warn(dir + " is not a directory");
			return;
		}
		if (!dir.canWrite()) {
			log.warn(dir + " is not writable");
			return;
		}
		int count = 1;
		for (Mail m : mails) {
			try {
				StringWriter w = new StringWriter();
				PrintWriter p = new PrintWriter(w);
				p.printf("%04d", Integer.valueOf(count));
				dumpObject(dir, w.toString(), count, m.getContent(), 
					m.getContentType(), uriList);
			} catch (Exception e) {
				log.warn("msg " + count + " - " + e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("method()", e);
				}
			}
			count++;
		}
	}
	
	/**
	 * @param args
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		if (args.length < 1) {
			System.err.println("Usage: java -cp ... MboxReader mboxFile [outfile]");
			System.exit(1);
		}
		MboxReader mr = new MboxReader();
		ArrayList<Mail> mails = MboxReader.read(new File(args[0]));
		ArrayList<URI> uriList = new ArrayList<URI>();
		String tmpdir = System.getProperty("java.io.tmpdir");
		if (tmpdir == null) {
			tmpdir ="/tmp";
		}
		File dir = new File(tmpdir, "mail");
		log.info("dumping to " + dir);
		mr.dump(dir, mails, uriList);
		TreeMap<String, TreeSet<String>> set = new TreeMap<String,TreeSet<String>>();
		log.info("Found " + uriList.size() + " URLs");
		StringBuilder buf = new StringBuilder();
		Whois whois = new Whois(null);
		for (URI uri : uriList) {
			String host = whois.getTldNormalizedDomain(uri.getHost());
			buf.append(host);
			buf.reverse();
			String dom = buf.toString();
			TreeSet<String> uset = set.get(dom);
			if (uset == null) {
				uset = new TreeSet<String>();
				set.put(dom, uset);
			}
			uset.add(uri.toString());
			buf.setLength(0);
		}
		OutputStream out = null;
		if (args.length > 1) {
			out = new FileOutputStream(args[1], false);
		} else {
			out = System.out;
		}
		out.write("<html><head><title>Spam analyse</title><head><body>".getBytes());
		for (Entry<String, TreeSet<String>> e : set.entrySet()) {
			buf.append(e.getKey());
			buf.reverse();
			buf.append("\n<ul>\n");
			for (String s : e.getValue()) {
				buf.append("<li><a href=\"").append(s).append("\">").append(s)
					.append("</a></li>\n");
			}
			buf.append("</ul>\n");
			out.write(buf.toString().getBytes());
			buf.setLength(0);
		}
		out.write("</html>\n".getBytes());
		if (args.length > 1) {
			out.close();
		}
		log.info(set.size() + " domains");
	}
}
