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
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.internet.ContentType;
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

	private boolean hexDump;

	/**
	 * Empty init.
	 */
	public MboxReader() {
		this(false);
	}

	/**
	 * Empty init.
	 * @param hexdump if {@code true} dump text files as hex as well.
	 */
	public MboxReader(boolean hexdump) {
		this.hexDump = hexdump;
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
							log.debug("read()", e);
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
				log.debug("read()", e);
			}
		}
		log.info("found " + msg.size() + " messages");
		return msg;
	}
	
	private static void dump(File file, byte[] content) {
		FileOutputStream fos = null; 
		try {
			fos = new FileOutputStream(file);
			fos.write(content);
		} catch (IOException e) {
			log.warn(e.getLocalizedMessage());
			if (log.isDebugEnabled()) {
				log.debug("dump()", e);
			}
		} finally {
			if (fos != null) {
				try { fos.close(); } catch (Exception e) { /* ignore */ }
			}
		}
	}

	private static final int PUNCT_MASK =  
		  (1 << Character.START_PUNCTUATION) 
        | (1 << Character.CONNECTOR_PUNCTUATION) 
        | (1 << Character.DASH_PUNCTUATION) 
        | (1 << Character.END_PUNCTUATION) 
        | (1 << Character.FINAL_QUOTE_PUNCTUATION)
        | (1 << Character.INITIAL_QUOTE_PUNCTUATION)
        | (1 << Character.OTHER_PUNCTUATION)
        ;

	private static final int MISC_MASK =  
		(1 << Character.CURRENCY_SYMBOL)
		| (1 << Character.OTHER_SYMBOL)
		| (1 << Character.OTHER_LETTER)
		| (1 << Character.MODIFIER_LETTER)
		;

      private static boolean isPunct(char c) {
        int type = Character.getType(c);
        return (type & PUNCT_MASK) != 0;
    }

    private static boolean isGraph(char c) {
        return Character.isLetterOrDigit(c) || isPunct(c) 
        	|| ((Character.getType(c) & MISC_MASK) != 0);
    }

	private static char printable(char c) {
		return isGraph(c) ? c : ' ';
	}

	@SuppressWarnings("boxing")
	private static void dumpHex(File file, String content) {
		PrintWriter out = null; 
		try {
			out = new PrintWriter(file, "UTF-8");
			char[] c = content.toCharArray();
			int rem = c.length & 0x07;
			int last = c.length - rem;
			Character[] p = new Character[8];
			for (int i=0; i < last; i += 8) {
				for (int k=0; k < 8; k++) {
					p[k] = printable(c[i+k]);
				}
				out.printf("%c %c %c %c  %c %c %c %c    "
					+ "%04x %04x %04x %04x  %04x %04x %04x %04x%n",
					p[0],p[1],p[2],p[3], p[4],p[5],p[6],p[7],
					Integer.valueOf(c[i]),Integer.valueOf(c[i+1]),
					Integer.valueOf(c[i+2]),Integer.valueOf(c[i+3]), 
					Integer.valueOf(c[i+4]),Integer.valueOf(c[i+5]),
					Integer.valueOf(c[i+6]),Integer.valueOf(c[i+7]));
			}
			if (rem == 0) {
				return;
			}
			char[] l = new char[8*2+1+4+8*5+2];
			Arrays.fill(l, ' ');
			l[l.length-1] = '\n';
			int offset = c.length - rem;
			for (int i=0, k=8*2+1+4; i < rem; i+=2, k+=5, offset++) {
				l[i] = printable(c[offset]);
				char[] val = String.format(Locale.US, "%04x", 
					Integer.valueOf(c[offset])).toCharArray();
				System.arraycopy(val, 0, l, k, 4);
				if (i == 6) {
					i++; k++;
				}
			}
			out.write(l);
		} catch (IOException e) {
			log.warn(e.getLocalizedMessage());
			if (log.isDebugEnabled()) {
				log.debug("dumpHex()", e);
			}
		} finally {
			if (out != null) {
				try { out.close(); } catch (Exception e) { /* ignore */ }
			}
		}
	}

	private void dumpObject(File dir, String prefix, int count, Object o,
		ContentType contentType, List<URI> uriList) 
	{
		log.info(ContentTypeMatcher.normalize(contentType));
		if (o instanceof String) {
			String s = o.toString();
			dump(new File(dir, prefix + ".txt"), 
				s.getBytes(Charset.forName("UTF-8")));
			if (hexDump) {
				dumpHex(new File(dir, prefix + ".txt-hex"), s);
			}
			WhoisCheck.findURIs(s, uriList);
		} else if (o instanceof MimeMultipart) {
			try {
				MimeMultipart part = (MimeMultipart) o;
				int idx = part.getCount();
				for (int i=0; i < idx; i++) {
					BodyPart bp = part.getBodyPart(i);
					ContentType ct = null;
					try {
						ct = bp.getContentTypeObj();
					} catch (Exception e) {
						if (e instanceof IOException) {
							Throwable cause = e.getCause();
							if (cause instanceof MessagingException) {
								e = (Exception) cause;
							}
						}
						log.warn("msg " + count + " - " + e.getLocalizedMessage());
						if (log.isDebugEnabled()) {
							log.debug("dumpObject", e);
						}
					}
					dumpObject(dir, prefix + "." + i, count, bp.getContent(), 
						ct, uriList);
				}
			} catch (Exception e) {
				if (e instanceof IOException) {
					Throwable cause = e.getCause();
					if (cause instanceof MessagingException) {
						e = (Exception) cause;
					}
				}
				log.warn("msg " + count + " - " + e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("dumpObject()", e);
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
					log.debug("dumpObject()", e);
				}
			} finally {
				try { in.close(); } catch (Exception x) { /* ignore */ }
			}
			String ext = contentType != null ? contentType.getSubType() : "";
			if (contentType != null && contentType.getPrimaryType().equals("text")) {
				String txt = ContentTypeMatcher.convert(contentType, bos.toByteArray());
				WhoisCheck.findURIs(txt, uriList);
				dump(new File(dir, prefix + "." + ext), 
					txt.getBytes(Charset.forName("UTF-8")));
				if (hexDump) {
					dumpHex(new File(dir, prefix + ".txt-hex"), txt);
				}
			} else {
				dump(new File(dir, prefix + "." + ext), bos.toByteArray());
			}
		} else if (o instanceof MimeMessage) {
			MimeMessage m = (MimeMessage) o;
			ContentType ct = null;
			try {
				ct = m.getContentTypeObj();
			} catch (Exception e) {
				if (e instanceof IOException) {
					Throwable cause = e.getCause();
					if (cause instanceof MessagingException) {
						e = (Exception) cause;
					}
				}
				log.warn("msg " + count + " - " + e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("dumpObject", e);
				}
			}
			try {
				dumpObject(dir, prefix, count, m.getContent(), ct, uriList);
			} catch (Exception e) {
				log.warn("msg " + count + " - " + e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("dumpObject()", e);
				}
			}
		} else {
			log.warn("Unable to handle msg " + count + " " 
				+ o.getClass().getSimpleName() + " " 
				+ ContentTypeMatcher.normalize(contentType));
		}
	}

	/**
	 * Dump all message parts to the given directory prefixed with the number 
	 * of message in mailbox order. *.txt file content is UTF-8 encoded, other
	 * are as read.
	 * 
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
					m.getContentTypeObj(), uriList);
			} catch (Exception e) {
				if (e instanceof IOException) {
					Throwable cause = e.getCause();
					if (cause instanceof MessagingException) {
						e = (Exception) cause;
					}
				}
				log.warn("msg " + count + " - " + e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("dump()", e);
				}
			}
			count++;
		}
	}
	
	/**
	 * Print Usage information for {@link #main(String[])}.
	 * @param out	where to print the usage infos.
	 */
	public static void usage(PrintStream out) {
		String EOL = System.getProperty("line.separator");
		out.println(
"Usage: java -cp ... MboxReader mboxFile [outfile]" + EOL + 
EOL +
"Reads in the given mbox formatted file and dumps the parts of each mail" + EOL +
"to java.io.tmpdir/mail/ (default /tmp/mail/). Last but not least URIs are " + EOL + 
"extracted from plain text, html and xml message parts and printed to " + EOL +
"the given outfile. If this parameter is ommited, it gets printed to stdout." + EOL +
"String based mail parts are dumped as UTF-8, all others as read in."
);
	}

	/**
	 * @param args
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		if (args.length < 1) {
			usage(System.err);
			System.exit(1);
		}
		String tmp = System.getProperty("hex", null);
		MboxReader mr = new MboxReader(tmp != null);
		ArrayList<Mail> mails = MboxReader.read(new File(args[0]));
		ArrayList<URI> uriList = new ArrayList<URI>();

		String os = System.getProperty("os.name", "");
		String tmpdir = System.getProperty("java.io.tmpdir");
		if (tmpdir == null || os.startsWith("Mac")) {
			tmpdir = "/tmp";
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
