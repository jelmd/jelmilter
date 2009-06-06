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
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.mail.BodyPart;
import javax.mail.Header;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.ovgu.cs.milter4j.util.Mail;
import de.ovgu.cs.milter4j.util.Misc;

/**
 * A simple or combined Rule.
 * 
 * @author 	Jens Elkner
 * @version	$Revision$
 */
public class Rule {
	private static final Logger log = LoggerFactory.getLogger(Rule.class);

	private String id;
	private boolean not = false;
	private boolean and = true;
	private Rule[] rules;
	private Source source;
	private String find;
	private Pattern pattern;
	private String[] keys;
	private EnumSet<Source> allSources;

	/**
	 * Evaluate the rule.
	 * <p>
	 * Depending on the state of mail reception, some or even all arguments
	 * might be {@code null} or empty.
	 * 
	 * @param from		arguments of the {@code MAIL FROM:} command
	 * @param rcpts		arguments of the {@code RCPT TO:} command.
	 * @param macros	all collected macros received up to now.
	 * @param headers	all collected headers
	 * @param mail		the reassebled mail
	 * @return a continue packet, if the rule does not match, the proper
	 * 		packet associated with the configured action otherwise.
	 */
	public boolean eval(String[] from, String[] rcpts, 
		HashMap<String,String> macros, List<Header> headers, Mail mail)
	{
		boolean res = false;
		if (isSimple()) {
			if (find == null && pattern == null) {
				return not ? true : false;
			}
			switch (source) {
				case MAIL_FROM:
					res = mailFrom(from);
					break;
				case RCPT_TO:
					res = recipientTo(rcpts);
					break;
				case HEADER:
					res = header(headers);
					break;
				case BODY:
					res = body(mail, macros);
					break;
			}
			if (res && id != null) {
				log.info("Rule \"{}\" matched", id);
			}
		} else if (rules != null) {
			boolean shortCut = false;
			for (int i=0; i < rules.length; i++) {
				boolean match = 
					rules[i].eval(from, rcpts, macros, headers, mail);
				if (and & !match) {
					shortCut = true;
					break;
				} else if (match & !and) {
					shortCut = true;
					res = true;
					break;
				}
			}
			if (!shortCut) {
				// all rules matched
				res = and ? true : false;
			}
		}
		return not ? !res : res;
	}
	
	private boolean mailFrom(String[] from) {
		if (from == null) {
			return not ? true : false;
		}
		boolean found = false;
		if (find != null) {
			for (int i=from.length-1; i >= 0; i--) {
				if (from[i].indexOf(find) != -1) {
					found = true;
					break;
				}
			}
		} else {
			Matcher m = pattern.matcher("");
			for (int i=from.length-1; i >= 0; i--) {
				m.reset(from[i]);
				if (m.find()) {
					found = true;
					break;
				}
			}
		}
		return not ? !found : found;
	}

	private boolean recipientTo(String[] to) {
		if (to == null) {
			return not ? true : false;
		}
		boolean found = false;
		if (find != null) {
			for (int i=to.length-1; i >= 0; i--) {
				if (to[i].indexOf(find) != -1) {
					found = true;
					break;
				}
			}
		} else {
			Matcher m = pattern.matcher("");
			for (int i=to.length-1; i >= 0; i--) {
				m.reset(to[i]);
				if (m.find()) {
					found = true;
					break;
				}
			}
		}
		return not ? !found : found;
	}

	private boolean header(List<Header> headers) {
		if (headers == null || headers.size() == 0) {
			return not ? true : false;
		}
		boolean found = false;
		Matcher matcher = pattern != null ? pattern.matcher("") : null;
		for (Header h : headers) {
			String hname = h.getName();
			String val = null;
			if (keys != null) {
				for (int i=0; i < keys.length; i++) {
					if (hname.equals(keys[i])) {
						val = h.getValue();
						break;
					}
				}
			} else {
				val = h.getValue();
			}
			if (val == null) {
				continue;
			}
			if (find != null) {
				if (val.indexOf(find) != -1) {
					found = true;
					break;
				}
			} else {
				matcher.reset(val);
				if (matcher.find()) {
					found = true;
					break;
				}
			}
		}
		return not ? !found : found;
	}
	
	private boolean matchesContent(String contentType) {
		for (int i=keys.length-1; i >= 0; i--) {
			if (contentType.toLowerCase().startsWith(keys[i])) {
				return true;
			}
		}
		return false;
	}
	
	private boolean checkMailObject(Object o, String contentType,
		HashMap<String,String> macros) 
	{
		if (o instanceof String) {
			if (matchesContent(contentType)) {
				String txt = o.toString().trim();
				if (find != null) {
					return txt.indexOf(find) != -1;
				}
				Matcher m = pattern.matcher(txt);
				return m.find();
			}
			return false;
		} else if (o instanceof MimeMultipart) {
			try {
				MimeMultipart part = (MimeMultipart) o;
				int idx = part.getCount();
				for (int i=0; i < idx; i++) {
					BodyPart bp = part.getBodyPart(i);
					if (checkMailObject(bp.getContent(), bp.getContentType(),
						macros)) 
					{
						return true;
					}
				}
			} catch (Exception e) {
				log.warn("MID: " + macros.get("Mi") + " " + e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("method()", e);
				}
			}
		} else if (o instanceof InputStream) {
			if (matchesContent(contentType)) {
				InputStream in = (InputStream) o;
				ByteArrayOutputStream bos = new ByteArrayOutputStream(4096);
				byte[] dst = new byte[4096];
				int read = 0;
				try {
					while ((read = in.read(dst)) != -1) {
						bos.write(dst, 0, read);
					}
				} catch (IOException e) {
					log.warn("MID: " + macros.get("Mi") + " " + e.getLocalizedMessage());
					if (log.isDebugEnabled()) {
						log.debug("method()", e);
					}
				} finally {
					try { in.close(); } catch (Exception x) { /* ignore */ }
				}
				String txt = new String(bos.toByteArray());
				if (find != null) {
					return txt.indexOf(find) != -1;
				}
				Matcher m = pattern.matcher(txt);
				return m.find();
			}
		} else if (o instanceof MimeMessage) {
			MimeMessage m = (MimeMessage) o;
			try {
				return checkMailObject(m.getContent(), m.getContentType(), macros);
			} catch (Exception e) {
				log.warn("MID: " + macros.get("Mi") + " " + e.getLocalizedMessage());
				if (log.isDebugEnabled()) {
					log.debug("method()", e);
				}
			}
		} else {
			log.warn("Unable to handle msg " + o.getClass().getSimpleName() 
				+ " " + contentType + " MID: " + macros.get("Mi"));
		}
		return false;
	}
	
	private boolean body(Mail mail, HashMap<String,String> macros) {
		if (mail == null) {
			return not ? true : false;
		}
		boolean res = false;
		try {
			res = checkMailObject(mail.getContent(), mail.getContentType(), macros);
		} catch (Exception e) {
			log.warn("MID:" + macros.get("Mi") + " " + e.getLocalizedMessage());
			if (log.isDebugEnabled()) {
				log.debug("method()", e);
			}
		}
		return not ? !res : res;
	}
	
	/**
	 * Check, whether this is a simple rule, i.e. corresponds to a 
	 * {@code find} or {@code match} element in the config file and does not
	 * contain any other rules.
	 * 
	 * @return {@code true} if this rule is a simple rule.
	 */
	public boolean isSimple() {
		return source != null;
	}

	/**
	 * Get the ID of the rule.
	 * @return might be {@code null}
	 */
	public String getId() {
		return id;
	}
	
	/**
	 * Get all sources, which are possibly involved in decision making.
	 * @return a possible empty set of sources.
	 */
	public EnumSet<Source> getSources() {
		if (allSources != null) {
			return allSources;
		}
		if (isSimple()) {
			allSources = EnumSet.of(source);
		} else {
			allSources = EnumSet.noneOf(Source.class);
			for (Rule r : rules) {
				allSources.addAll(r.getSources());
			}
		}
		return allSources;
	}
	
	/**
	 * Configure this rule by reading the given stream.
	 * @param in	a stream, whoms cursor points to the start of an {@code and},
	 * 		{@code or}, {@code find} or {@code match} element.
	 * @throws XMLStreamException
	 */
	public void fromXml(XMLStreamReader in) throws XMLStreamException {
		String tmp = in.getLocalName();
		id = in.getAttributeValue(null, "id");
		source = null;
		keys = null;
		pattern = null;
		find = null;
		rules = null;
		Boolean isFind = null;
		if (tmp.equals("and")) {
			and = true;
		} else if (tmp.equals("or")) {
			and = false;
		} else if (tmp.equals("find")) {
			isFind = Boolean.TRUE;
		} else if (tmp.equals("match")) {
			isFind = Boolean.FALSE;
		} else {
			throw new XMLStreamException("Unexpected element '" 
				+ in.getLocalName() 
				+ "' expecting 'and' | 'or' | 'find' | 'match'", 
				in.getLocation());
		}
		tmp = in.getAttributeValue(null, "not");
		not = tmp != null && tmp.equals("true");
		if (isFind != null) {
			tmp = in.getAttributeValue(null, "src");
			try {
				source = Source.valueOf(tmp.toUpperCase());
			} catch (Exception e) {
				log.warn(e.getLocalizedMessage());
			}
			if (source == null) {
				throw new XMLStreamException("'src' attribute required", 
					in.getLocation());
			}
			if (source == Source.HEADER) {
				tmp = in.getAttributeValue(null, "name");
				if (tmp != null && tmp.length() > 0) {
					keys = tmp.split(",");
				}
			} else if (source == Source.BODY) {
				tmp = in.getAttributeValue(null, "type");
				if (tmp != null && tmp.length() > 0) {
					keys = tmp.split(",");
				} else {
					keys = new String[] { "text/" };
				}
			}
			tmp = in.getElementText();
			if (isFind == Boolean.TRUE) {
				find = tmp;
			} else {
				
				try {
					pattern = Pattern.compile(tmp);
				} catch (Exception e) {
					throw new XMLStreamException("Invalid pattern for rule '"
						+ id + "' - " + e.getLocalizedMessage(), in.getLocation());
				}
			}
		} else {
			ArrayList<Rule> nRules = new ArrayList<Rule>();
			while (in.hasNext()) {
				int ev = in.next();
				if (ev == XMLStreamConstants.END_ELEMENT) {
					break;
				}
				if (ev == XMLStreamConstants.START_ELEMENT) {
					tmp = in.getLocalName();
					if (tmp.equals("and") || tmp.equals("or") 
						|| tmp.equals("find") || tmp.equals("match")) 
					{
						Rule rule = new Rule();
						rule.fromXml(in);
						if (!rule.getSources().isEmpty()) {
							nRules.add(rule);
						}
					} else {
						log.warn("Ignoring unknown element '" + tmp + "'");
						Misc.fastForwardToEndOfElement(in);
					}
				}
			}
			rules = nRules.toArray(new Rule[nRules.size()]);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder(getClass().getSimpleName())
			.append("[id=").append(id).append(";src=").append(source.name())
			.append(";allSrc=");
		if (allSources == null) {
			buf.append("null");
		} else {
			for (Source s : allSources) {
				buf.append(s.name()).append(',');
			}
			buf.setLength(buf.length()-1);
		}
		if (isSimple()) {
			buf.append(';');
			if (not) {
				buf.append('!');
			}
			if (find != null) {
				buf.append("find=").append(find);
			}
			if (pattern != null) {
				buf.append("pattern=").append(pattern.pattern());
			}
		}
		if (keys != null && keys.length > 0) {
			buf.append(";keys=");
			for (int i=0; i < keys.length; i++) {
				buf.append(keys[i]).append(',');
			}
			buf.setLength(buf.length()-1);
		}
		if (!isSimple()) {
			buf.append(';');
			if (not) {
				buf.append('!');
			}
			buf.append(and ? "and=" : "or=");
			if (rules != null && rules.length > 0) {
				for (int i=0; i < rules.length; i++) {
					buf.append(rules[i].toString()).append(',');
				}
				buf.setLength(buf.length()-1);
			}
		}
		buf.append(']');
		return buf.toString();
	}
}
