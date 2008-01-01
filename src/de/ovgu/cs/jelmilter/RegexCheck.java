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
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
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
import de.ovgu.cs.jelmilter.misc.RuleSet;
import de.ovgu.cs.jelmilter.misc.Source;
import de.ovgu.cs.milter4j.MailFilter;
import de.ovgu.cs.milter4j.cmd.Type;
import de.ovgu.cs.milter4j.reply.AcceptPacket;
import de.ovgu.cs.milter4j.reply.ContinuePacket;
import de.ovgu.cs.milter4j.reply.Packet;
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
			commands = EnumSet.noneOf(Type.class);
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
			log.warn(e.getLocalizedMessage());
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
	public Packet doMailFrom(String[] from) {
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
		return eval(Source.MAIL_FROM, from, null, null, null, null);
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

	private Packet eval(Source current, String[] from, String[] rcpts, 
		HashMap<String,String> macros, List<Header> headers, Mail mail)
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
					log.info(getLogInfo(macros) + "RuleSet \"{}\" matched", 
						ruleSet[currentRuleIdx].getId());
					return p;
				}
			}
		} finally {
			lock.unlock();
		}
		return new ContinuePacket();		
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Packet doRecipientTo(String[] recipient) {
		if (maxSize == 0) {
			return null;
		}
		recipientsTo = recipient;
		return eval(Source.RCPT_TO, mailFrom, recipientsTo, null, null, null);
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
		return eval(Source.HEADER, mailFrom, recipientsTo, macros, headers, null);
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
				l.add(new AcceptPacket(false));
				return l;
			}
		} catch (MessagingException e) {
			// ignore
		}
		Packet p = 
			eval(Source.BODY, mailFrom, recipientsTo, macros, headers, mail);
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
		while(in.hasNext()) {
			int ev = in.next();
			if (ev == XMLStreamConstants.END_ELEMENT) {
				break;
			} else if (ev == XMLStreamConstants.START_ELEMENT) {
				tmp = in.getLocalName();
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
		ruleSet = rsets.toArray(new RuleSet[rsets.size()]);
		log.info("Found " + ruleSet.length + " valid rules");
		currentRuleIdx = 0;
	}
	
	/**
	 * @param args	0 .. the mbox file to read and scan, [1 .. the config file to use]
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		if (args.length < 1) {
			System.err.println("Usage: java -cp ... RegexCheck mboxFile [configFile]");
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
			try {
				Packet p = null;
				if (cmds.contains(Type.EOH)) {
					Enumeration<?> h = mail.getAllHeaders();
					ArrayList<Header> headers = new ArrayList<Header>();
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
					List<Packet> l = rc.doEndOfMail(null, null, mail);
					if (l != null) {
						for (Packet lp : l) {
							if (lp.getType() != de.ovgu.cs.milter4j.reply.Type.CONTINUE) {
								log.info("msg " + count + ": " + lp.toString());
							}
						}
					}
				}
			} catch (MessagingException e) {
				log.warn(e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("method()", e);
				}
			}
		}
	}
}
