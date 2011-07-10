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

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import javax.mail.Header;
import javax.mail.MessagingException;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.stream.StreamSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.ovgu.cs.jelmilter.misc.MboxReader;
import de.ovgu.cs.jelmilter.misc.Rule;
import de.ovgu.cs.jelmilter.misc.RuleSet;
import de.ovgu.cs.jelmilter.misc.Source;
import de.ovgu.cs.milter4j.MailFilter;
import de.ovgu.cs.milter4j.cmd.Type;
import de.ovgu.cs.milter4j.reply.AcceptPacket;
import de.ovgu.cs.milter4j.reply.ContinuePacket;
import de.ovgu.cs.milter4j.reply.Packet;
import de.ovgu.cs.milter4j.reply.ReplyPacket;
import de.ovgu.cs.milter4j.util.Mail;
import de.ovgu.cs.milter4j.util.Misc;

/**
 * A Filter, which checks mails against regular expression or just the occurance 
 * of a string.
 * 
 * @author 	Jens Elkner
 * @version	$Revision$
 */
public class RegexCheck
	extends MailFilter
{
	private static final Logger log = LoggerFactory.getLogger(RegexCheck.class);

	/** Default file name of the configuration file */
	public static final String DEFAULT_CONFIG = "/etc/mail/regex.conf";
	/** the defasult max. message size to be considered as spam */
	public static final int DEFAUL_MAX_SIZE = 50 * 1024;
	
	
	private String[] mailFrom;
	private String[] recipientsTo;
	private static final AtomicInteger instCounter = new AtomicInteger();
	private String name;
	private RuleSet[] ruleSet;
	private int currentRuleIdx;
	private int maxSize;
	private File configFile;
	private ReentrantLock lock = new ReentrantLock();
	private EnumSet<Type> commands;
	private String statName;

	/**
	 * Create a new instance.
	 * @param configFile	config file to use. If {@code null}, the default
	 * 		config filename will be used instead.
	 */
	public RegexCheck(String configFile) {
		this();
		reconfigure(configFile == null || configFile.length() == 0 
			? DEFAULT_CONFIG : configFile);
	}
	
	/**
	 * Create a un-initialized instance.
	 */
	protected RegexCheck() {
		name = "RegexCheck " + instCounter.getAndIncrement();
		maxSize = 0;
		ruleSet = new RuleSet[0];
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public EnumSet<Type> getCommands() {
		if (commands != null) {
			return commands;
		}
		lock.lock();
		try {
			EnumSet<Source> src = EnumSet.noneOf(Source.class);
			for (int i=ruleSet.length-1; i >=0; i--) {
				src.addAll(ruleSet[i].getSources());
			}
			commands = EnumSet.of(Type.MACRO); // for logging we want macros
			if (src.contains(Source.MAIL_FROM)) {
				commands.add(Type.MAIL);
			}
			if (src.contains(Source.RCPT_TO)) {
				commands.add(Type.RCPT);
			}
			if (src.contains(Source.HEADER)) {
				commands.add(Type.HEADER);
				commands.add(Type.EOH);
			}
			if (src.contains(Source.BODY)) {
				commands.add(Type.BODY);
				commands.add(Type.BODYEOB);
			}
		} finally {
			lock.unlock();
		}
		return commands;
	}
	
	/**
	 * Need re-assembled mails to be able to scan the body parts right.
	 * @return {@code true}.
	 */
	@Override
	public boolean reassembleMail() {
		return getCommands().contains(Type.BODYEOB);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doAbort() {
		mailFrom = null;
		recipientsTo = null;
		currentRuleIdx = 0;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doQuit() {
		mailFrom = null;
		recipientsTo = null;
		currentRuleIdx = 0;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public MailFilter getInstance() {
		RegexCheck re = new RegexCheck();
		re.mailFrom = mailFrom;
		re.recipientsTo = recipientsTo;
		re.ruleSet = ruleSet;
		re.maxSize = maxSize;
		re.configFile = configFile;
		re.statName = statName;
		re.commands = commands;
		return re;
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
	public String getStatName() {
		return statName == null ? super.getStatName() : statName;
	}
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean reconfigure(String param) {
		if (param != null) {
			configFile = new File(param);
		}
		lock.lock();
		commands = null;
		StreamSource src = null;
		XMLStreamReader in = null;
		try {
			src = Misc.getInputSourceByFile(configFile, false);
			if (src != null) {
				in = Misc.getReader(src, "regex", false);
				if (in != null) {
					fromXml(in);
				}
			}
		} catch (Exception e) {
			log.warn(e.getLocalizedMessage(), e);
			if (log.isDebugEnabled()) {
				log.debug("reconfigure", e);
			}
		} finally {
			lock.unlock();
			if (in != null) {
				try { in.close(); } catch (Exception e) { /* ignore */ }
			}
			if (src != null) {
				try { src.getInputStream().close(); } catch (Exception e) {
					// nothing we can do here
				}
			}
		}
		return true;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Packet doMailFrom(String[] from, HashMap<String,String> macros) {
		if (maxSize == 0) {
			return null;
		}
		mailFrom = from;
		if (currentRuleIdx != 0) {
			log.warn("rule index has not been reset to zero");
			currentRuleIdx = 0;
		}
		if (maxSize != -1) {
			for (int i=from.length-1; i >= 0; i--) {
				if (from[i].startsWith("SIZE=")) {
					try {
						int s = Integer.parseInt(from[i].substring(5));
						if (s > maxSize) {
							return new AcceptPacket(false);
						}
					} catch (Exception e) {
						// don't care
					}
					break;
				}
			}
		}
		try {
			return eval(Source.MAIL_FROM, from, null, null, null, null);
		} catch (Exception e) {
			if (e instanceof IOException) {
				Throwable cause = e.getCause();
				if (cause instanceof MessagingException) {
					e = (Exception) cause;
				}
			}
			log.warn("doMailFrom" + Rule.getMessageID(macros) 
				+ e.getLocalizedMessage());
			if (log.isDebugEnabled()) {
				log.debug("doRecipientTo", e);
			}
		}
		return createReplyMaleformedMsg();
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
		} else if (mailFrom != null) {
			for (int i=mailFrom.length-1; i >= 0; i--) {
				if (mailFrom[i].indexOf('=') == -1) {
					buf.append(mailFrom[i]).append(',');
				}
			}
			if (buf.charAt(buf.length()-1) == ',') {
				buf.setLength(buf.length()-1);
			}
		}
		buf.append("' via='");
		tmp = macros.get("_");
		if ( tmp != null) {
			buf.append(tmp);
		}
		buf.append("'  ");
		return buf.toString();
	}

	private Packet eval(Source current, String[] from, String[] rcpts, 
		HashMap<String,String> macros, List<Header> headers, Mail mail)
		throws MessagingException, IOException
	{
		EnumSet<Source> tilNow = EnumSet.range(Source.MAIL_FROM, current);
		// go as far as we can
		lock.lock();
		try {
			for (; currentRuleIdx < ruleSet.length; currentRuleIdx++) {
				if (!tilNow.containsAll(ruleSet[currentRuleIdx].getSources())) {
					return new ContinuePacket();
				}
				Packet p = ruleSet[currentRuleIdx]
				    .eval(from, rcpts, macros, headers, mail);
				if (p != null && p.getType() != de.ovgu.cs.milter4j.reply.Type.CONTINUE) {
					log.info(getLogInfo(macros) + "RuleSet {} \"{}\" matched",
						Integer.valueOf(currentRuleIdx),
						ruleSet[currentRuleIdx].getId());
					return p;
				}
			}
		} finally {
			lock.unlock();
		}
		return new ContinuePacket();		
	}

	private static ReplyPacket createReplyMaleformedMsg() {
		return new ReplyPacket(554, "5.7.1", 
			"Invalid message format - strict RFC compliance required");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Packet doRecipientTo(String[] recipient, HashMap<String,String> macros) 
	{
		if (maxSize == 0) {
			return null;
		}
		recipientsTo = recipient;
		try {
			return eval(Source.RCPT_TO, mailFrom, recipientsTo, null, null, null);
		} catch (Exception e) {
			if (e instanceof IOException) {
				Throwable cause = e.getCause();
				if (cause instanceof MessagingException) {
					e = (Exception) cause;
				}
			}
			log.warn("doRecipientTo" + Rule.getMessageID(macros) 
				+ e.getLocalizedMessage());
			if (log.isDebugEnabled()) {
				log.debug("doRecipientTo", e);
			}
		}
		return createReplyMaleformedMsg();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Packet doEndOfHeader(List<Header> headers, 
		HashMap<String,String> macros) 
	{
		if (maxSize == 0) {
			return null;
		}
		try {
			return eval(Source.HEADER, mailFrom, recipientsTo, macros, headers, 
				null);
		} catch (Exception e) {
			if (e instanceof IOException) {
				Throwable cause = e.getCause();
				if (cause instanceof MessagingException) {
					e = (Exception) cause;
				}
			}
			log.warn("doEndOfHeader" + Rule.getMessageID(macros) 
				+ e.getLocalizedMessage());
			if (log.isDebugEnabled()) {
				log.debug("doEndOfHeader", e);
			}
		}
		return createReplyMaleformedMsg();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<Packet> doEndOfMail(List<Header> headers, 
		HashMap<String,String> macros, Mail mail) 
	{
		if (maxSize == 0) {
			return null;
		}
		ArrayList<Packet> l = new ArrayList<Packet>();
		try {
			// MAIL FROM: has not always a SIZE= value
			if (maxSize > 0 && mail.getSize() > maxSize) {
				if (log.isDebugEnabled()) {
					log.debug(getLogInfo(macros) + "size=" + mail.getSize());
				}
				l.add(new AcceptPacket(false));
				return l;
			}
		} catch (MessagingException e) {
			// ignore
		}
		Packet p = null;
		try {
			p = eval(Source.BODY, mailFrom, recipientsTo, macros, headers, mail);
		} catch (Exception e) {
			if (e instanceof IOException) {
				Throwable cause = e.getCause();
				if (cause instanceof MessagingException) {
					e = (Exception) cause;
				}
			}
			log.warn("doEndOfMail" + Rule.getMessageID(macros) 
				+ e.getLocalizedMessage());
			if (log.isDebugEnabled()) {
				log.debug("doEndOfMail", e);
			}
			p = createReplyMaleformedMsg();
		}
		if (p != null) {
			l.add(p);
			return l;
		}
		return null;
	}
	
	/**
	 * Get the upper size limit for mails, which should be scanned. 
	 * @return {@code -1} if no limit is set, the limit otherwise.
	 */
	public int getMaxSize() {
		return maxSize;
	}

	/**
	 * Configure this instance by reading the given stream
	 * @param in	a stream, whoms cursor points to the start of an {@code regex}
	 * 		element.
	 * @throws XMLStreamException
	 */
	public void fromXml(XMLStreamReader in) throws XMLStreamException {
		if (!in.getLocalName().equals("regex")) {
			throw new XMLStreamException("Unexpected element '" 
				+ in.getLocalName() + "' expecting 'regex'", in.getLocation());
		}
		String tmp = in.getAttributeValue(null, "maxsize");
		int x = -1;
		if (tmp != null && tmp.length() > 0) {
			try {
				x = Integer.parseInt(tmp); 
			} catch (Exception e) {
				log.warn(Misc.xmlLocation2string(in.getLocation()) 
					+ " maxsize '" + tmp + "' is not a number");
			}
		}
		maxSize = x < 0 ? -1 : x;
		log.info("maxsize set to " + maxSize);
		statName = in.getAttributeValue(null, "id");
		if (statName != null) {
			statName = statName.trim();
			if (statName.length() > 0) {
				statName = this.getClass().getSimpleName() + " (" + statName + ")"; 
			} else {
				statName = null;
			}
		}
		ArrayList<RuleSet> rsets = new ArrayList<RuleSet>();
		LinkedList<XMLStreamReader> readerStack = 
			new LinkedList<XMLStreamReader>();
		HashMap<XMLStreamReader, StreamSource> closeOnReturn = 
			new HashMap<XMLStreamReader, StreamSource>();
		readerStack.push(in);
		try {
			while (!readerStack.isEmpty()) {
				in = readerStack.pop();
				while(in.hasNext()) {
					int ev = in.next();
					if (ev == XMLStreamConstants.END_ELEMENT) {
						break;
					} else if (ev == XMLStreamConstants.START_ELEMENT) {
						tmp = in.getLocalName();
						if (tmp.equals("xinclude")) {
							String file = in.getAttributeValue(null, "file");
							Misc.fastForwardToEndOfElement(in);
							if (file == null) {
								log.warn("Missing file attribute for include eleent");
								continue;
							}
							File inc = file.startsWith("/")
								? new File(file)
								: new File(new File(in.getLocation().getSystemId())
									.getParentFile(), file);
							if (! (inc.exists() && inc.isFile() && inc.canRead())) {
								log.warn("Unable to include file " + file);
								continue;
							}
							try {
								StreamSource src = 
									Misc.getInputSourceByFile(inc, false);
								XMLStreamReader in2 = 
									Misc.getReader(src, "regex", false);
								if (in2 != null) {
									readerStack.push(in);
									readerStack.push(in2);
									closeOnReturn.put(in2, src);
									break;
								}
							} catch (IOException e) {
								log.warn(e.getLocalizedMessage());
								if (log.isDebugEnabled()) {
									log.debug("fromXml()", e);
								}
								continue;
							}
						}
						if (tmp.equals("rule")) {
							RuleSet rs = new RuleSet();
							rs.fromXml(in);
							if (!rs.getSources().isEmpty()) {
								rsets.add(rs);
							}
						} else {
							log.warn("Ignoring unknown element '" + tmp + "'");
							Misc.fastForwardToEndOfElement(in);
						}
					}
				}
			}
		} finally {
			for (Entry<XMLStreamReader,StreamSource> e : closeOnReturn.entrySet()) {
				try { e.getKey().close(); } catch (Exception xx) { /* ignore */ }
				try { 
					e.getValue().getInputStream().close(); 
				} catch (Exception xx) { 
					/* ignore */ 
				}
			}
		}
		ruleSet = rsets.toArray(new RuleSet[rsets.size()]);
		log.info("Found " + ruleSet.length + " valid rules");
		currentRuleIdx = 0;
	}
	
	/**
	 * Print usage info for {@link #main(String[])}.
	 * @param out where to print
	 */
	public static void usage(PrintStream out) {
		String EOL = System.getProperty("line.separator");
		out.println(
"Usage: java -cp ... RegexCheck mboxFile [configFile]" + EOL +
EOL +
"Parse the given mbox formatted file and apply the regex rules from the " + EOL +
"the given config file. If no configFile is given, " + DEFAULT_CONFIG + EOL +
"will be used instead." + EOL +
"NOTE: Since messages are read from an mbox, envelope targets like " + EOL +
"       rcpt_to, mail_from as well as macros are not available!"
);
	}

	/**
	 * @param args	0 .. the mbox file to read and scan, [1 .. the config file to use]
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		if (args.length < 1) {
			usage(System.err);
			System.exit(1);
		}
		RegexCheck rc = new RegexCheck(args.length > 1 ? args[1] : null);
		ArrayList<Mail> mails = MboxReader.read(new File(args[0]));
		EnumSet<Type> cmds = rc.getCommands();
		if (cmds.contains(Type.MAIL)) {
			log.warn("'MAIL FROM:' targets not called (not available)");
		}
		if (cmds.contains(Type.RCPT)) {
			log.warn("'RCPT TO:' targets not called (not available)");
		}
		int count = 0;
		for (Mail mail : mails) {
			count++;
			log.info("Checking message " + count + "...");
			try {
				ArrayList<Header> headers = null;
				Packet p = null;
				if (cmds.contains(Type.EOH)) {
					Enumeration<?> h = mail.getAllHeaders();
					headers = new ArrayList<Header>();
					while (h.hasMoreElements()) {
						headers.add((Header) h.nextElement());
					}
					p = rc.doEndOfHeader(headers, null);
				}
				if (p != null 
					&& p.getType() != de.ovgu.cs.milter4j.reply.Type.CONTINUE) 
				{
					log.info("msg " + count + ": " + String.valueOf(p));
					continue;
				}
				if (cmds.contains(Type.BODYEOB)) {
					List<Packet> l = rc.doEndOfMail(headers, null, mail);
					if (l != null) {
						for (Packet lp : l) {
							if (lp.getType() != de.ovgu.cs.milter4j.reply.Type.CONTINUE) {
								log.info("msg " + count + ": " + lp.toString());
							}
						}
					}
				}
				rc.doQuit();
			} catch (MessagingException e) {
				log.warn(e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("main()", e);
				}
			}
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder(getClass().getSimpleName())
			.append("[cmds=");
		for (Type t : commands) {
			buf.append(t.name()).append(',');
		}
		buf.setLength(buf.length()-1);
		buf.append(";name=").append(name)
			.append(";maxSize=").append(maxSize)
			.append(";rule=").append(ruleSet[currentRuleIdx].toString()).append(')')
			.append(";statName=").append(statName)
			.append(";config=").append(configFile);
		if (mailFrom != null && mailFrom.length > 0) {
			buf.append(";MAIL FROM=[");
			for (int i=0; i < mailFrom.length; i++) {
				buf.append(mailFrom[i]).append("][");
			}
			buf.setLength(buf.length()-1);
		}
		if (recipientsTo != null && recipientsTo.length > 0) {
			buf.append(";RCPT TO=[");
			for (int i=0; i < recipientsTo.length; i++) {
				buf.append(recipientsTo[i]).append("][");
			}
			buf.setLength(buf.length()-1);
		}
		buf.append(']');
		return buf.toString();
	}
}
