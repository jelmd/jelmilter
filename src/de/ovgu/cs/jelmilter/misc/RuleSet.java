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
package de.ovgu.cs.jelmilter.misc;

import java.io.IOException;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;

import jakarta.mail.Header;
import jakarta.mail.MessagingException;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.ovgu.cs.milter4j.reply.AcceptPacket;
import de.ovgu.cs.milter4j.reply.ContinuePacket;
import de.ovgu.cs.milter4j.reply.DiscardPacket;
import de.ovgu.cs.milter4j.reply.Packet;
import de.ovgu.cs.milter4j.reply.RejectPacket;
import de.ovgu.cs.milter4j.reply.ReplyPacket;
import de.ovgu.cs.milter4j.reply.TempFailPacket;
import de.ovgu.cs.milter4j.util.Mail;
import de.ovgu.cs.milter4j.util.Misc;

/**
 * A class, which represents the {@code rule} element in the config file.
 * 
 * @author 	Jens Elkner
 * @version	$Revision$
 */
public class RuleSet {
	private static final Logger log = LoggerFactory
		.getLogger(RuleSet.class);

	private String id;
	private Action onmatch;
	private boolean force;
	private int reply;
	private String xcode;
	private String message;
	private Rule rule;

	/**
	 * Evaluate the rule.
	 * <p>
	 * Depending on the state of mail reception, soe or even all arguments
	 * might be {@code null} or empty.
	 * 
	 * @param from		arguments of the {@code MAIL FROM:} command
	 * @param rcpts		arguments of the {@code RCPT TO:} command.
	 * @param macros	all collected macros received up to now.
	 * @param headers	all collected headers
	 * @param mail		the reassebled mail
	 * @return a continue packet, if the rule does not match, the proper
	 * 		packet associated with the configured action otherwise.
	 * @throws IOException 
	 * @throws MessagingException 
	 */
	public Packet eval(String[] from, String[] rcpts, 
		HashMap<String,String> macros, List<Header> headers, Mail mail) 
		throws MessagingException, IOException
	{
		if (rule == null || !rule.eval(from, rcpts, macros, headers, mail)) {
			return new ContinuePacket();
		}
		switch (onmatch) {
			case DISCARD:
				return new DiscardPacket();
			case ACCEPT:
				return new AcceptPacket(force);
			case REJECT:
				return reply == -1 
					? new RejectPacket() 
					: new ReplyPacket(reply, xcode, message);
			case TEMPFAIL:
				return new TempFailPacket();
		}
		return null;
	}
	
	/**
	 * Get the ID of the rule.
	 * @return might be {@code null}
	 */
	public String getId() {
		return id;
	}
	
	/**
	 * Get all sources, which are possibly involved indecision making.
	 * @return a possible empty set of sources.
	 */
	public EnumSet<Source> getSources() {
		return rule == null ? EnumSet.noneOf(Source.class) : rule.getSources();
	}
	
	@SuppressWarnings("unused")
	private void parseMessage(XMLStreamReader in) throws XMLStreamException {
		String tmp = in.getAttributeValue(null, "reply");
		reply = -1;
		if (tmp != null && tmp.length() > 0) {
			try {
				reply = Integer.parseInt(tmp);
			} catch (Exception e) {
				log.warn(Misc.xmlLocation2string(in.getLocation()) 
					+ "reply code is not a number");
			}
		}
		xcode = in.getAttributeValue(null, "status");
		message = in.getElementText();
		if (reply == -1) {
			message = null;
			xcode = null;
		} else {
			try {
				new ReplyPacket(reply, xcode, message);
			} catch (Exception e) {
				log.warn(Misc.xmlLocation2string(in.getLocation())
					+ " - " + e.getLocalizedMessage());
				reply = -1;
				xcode = null;
				message = null;
			}
		}
	}
	
	/**
	 * Initialize this ruleset by reading the given stream.
	 * @param in	a stream, whomms cursor points to the start of an {@code rule}
	 * 		element
	 * @throws XMLStreamException
	 */
	public void fromXml(XMLStreamReader in) throws XMLStreamException {
		if (!in.getLocalName().equals("rule")) {
			throw new XMLStreamException("Unexpected element '" 
				+ in.getLocalName() + "' expecting 'rule'", in.getLocation());
		}
		id = in.getAttributeValue(null, "id");
		Action action = null;
		String tmp = in.getAttributeValue(null, "onmatch");
		if (tmp != null) {
			try {
				action = Action.valueOf(tmp.toUpperCase());
			} catch (Exception e) {
				log.warn(e.getLocalizedMessage());
			}
		}
		if (action == null) {
			log.warn("No valid action found in rule '" + id 
				+ "' - skipping rule");
			Misc.fastForwardToEndOfElement(in);
			return;
		}
		onmatch = action;
		tmp = in.getAttributeValue(null, "force");
		force = tmp != null && tmp.equals("true");
		rule = null;
		while (in.hasNext()) {
			int ev = in.next();
			if (ev == XMLStreamConstants.END_ELEMENT) {
				break;
			}
			if (ev == XMLStreamConstants.START_ELEMENT) {
				tmp = in.getLocalName();
				if (tmp.equals("msg")) {
					parseMessage(in);
				} else if (tmp.equals("and") || tmp.equals("or")) {
					if (rule != null) {
						log.warn(Misc.xmlLocation2string(in.getLocation())
							+ "only ONE 'and'|'or' is allowed per rule "
							+ "- only the first one will be used.");
						Misc.fastForwardToEndOfElement(in);
					} else {
						rule = new Rule();
						rule.fromXml(in);
					}
				} else {
					log.warn("Ignoring unknown element '" + tmp + "'");
					Misc.fastForwardToEndOfElement(in);
				}
			}
		}
		if (reply == 0) {
			// accept messages do not need a reply code
			reply = -1;
			xcode = null;
			message = null;
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return getClass().getSimpleName() + "[id=" + id 
			+ ";action=" + onmatch
			+ ";force=" + force
			+ ";reply=" + reply
			+ ";xcode=" + xcode
			+ ";msg=" + message
			+ ";rule=" + rule + ']';
	}
}
