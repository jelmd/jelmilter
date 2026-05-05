/**
 * Copyright (c) 2005-2011 Jens Elkner.
 * All Rights Reserved.
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package de.ovgu.cs.jelmilter.misc;

import java.nio.charset.Charset;
import java.util.Enumeration;
import java.util.Locale;

import jakarta.mail.internet.ContentType;
import jakarta.mail.internet.ParameterList;
import jakarta.mail.internet.ParseException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author 	Jens Elkner
 * @version	$Revision$
 */
public class ContentTypeMatcher {
	private static final Logger log = LoggerFactory.getLogger(ContentTypeMatcher.class);
	private String[] type;
	private String[] subtype;
	private String[][] params;
	private static final String CHARSET = "charset";
	
	/**
	 * Create a content matcher from the given raw content type value string.
	 * Format: {@code type['|'type]*'/'subtype['|'subtype]* [; param="val['|'val]*"]*}
	 * <p>
	 * An asterisk ({@code *}) may be used for type as well as subtype to match
	 * any [sub]type. The parameter names (param) are always trimmed and 
	 * converted to lower case. As seen, alternate values might be separated
	 * by a '|'. E.g.:
	 * <pre>
	 * text/plain|html; charset="windows-1251"
	 * </pre>
	 * @param raw the content type value as described above.
	 * @throws ParseException
	 */
	public ContentTypeMatcher(String raw) throws ParseException {
		ContentType ct = new ContentType(raw);
		String tmp = ct.getPrimaryType().trim().toLowerCase(Locale.ENGLISH);
		if (tmp.equals("*")) {
			type = new String[0];
		} else {
			type = tmp.split("\\|");
			for (int i=type.length-1; i >= 0; i--) {
				type[i] = type[i].trim();
			}
		}
		tmp = ct.getSubType().toLowerCase(Locale.ENGLISH);
		if (tmp.equals("*")) {
			subtype = new String[0];
		} else {
			subtype = tmp.split("\\|");
			for (int i=subtype.length-1; i >= 0; i--) {
				subtype[i] = subtype[i].trim();
			}
		}
		ParameterList pl = ct.getParameterList();
		if (pl != null) {
			params = new String[pl.size()][];
			int count = 0;
			Enumeration<?> names = pl.getNames();
			while (names.hasMoreElements()) {
				String name = names.nextElement().toString();
				// tokenizer removes quotes from values automatically
				String[] vals = pl.get(name).split("\\|");
				params[count] = new String[vals.length+1];
				name = name.toLowerCase(Locale.ENGLISH);
				if (name.equals(CHARSET)) {
					params[count][0] = CHARSET;				
					for (int i=0; i < vals.length; i++) {
						params[count][i+1] = vals[i].trim().toLowerCase(Locale.ENGLISH);
					}
				} else {
					params[count][0] = name;
					for (int i=0; i < vals.length; i++) {
						params[count][i+1] = vals[i].trim();
					}
				}
			}
		} else {
			params = new String[0][];
		}
	}
	
	/**
	 * Check, whether the given content type matches the criteria of this 
	 * instance. The content type matches, if a matching media type and subtype
	 * can be found. In addition, if paramters are given in the constructor, 
	 * <b>all</b> parameters must occure in the given content type and match
	 * at least one of the possibly alternate values.
	 * <p>
	 * Types and parameter names are trimmed and converted to lowercase and 
	 * matched on a <em>isEqual</em> base.
	 * <p>
	 * Parameter values are matched on a <em>startsWith</em> base, if the
	 * constructor param ends with an asterisk '*', matched on a <em>endsWith</em>
	 * base, if the constructor param starts with an asterisk '*', otherwise
	 * matched on a <em>isEqual</em> base.
	 * 
	 * @param ct	content type to compare to. If {@code null}, this method
	 * 	always returns {@code false}.
	 * @return {@code true} on match.
	 */
	public boolean matches(ContentType ct) {
		if (ct == null) {
			return false;
		}
		if (type.length > 0) {
			String st = ct.getPrimaryType().toLowerCase(Locale.ENGLISH);
			for (int i=type.length-1; i >= 0; i--) {
				if (type[i].equals(st)) {
					st = null;
					break;
				}
			}
			if (st != null) {
				return false;
			}
		}
		if (subtype.length > 0) {
			String st = ct.getSubType().trim().toLowerCase(Locale.ENGLISH);
			for (int i=subtype.length-1; i >= 0; i--) {
				if (subtype[i].equals(st)) {
					st = null;
					break;
				}
			}
			if (st != null) {
				return false;
			}
		}
		if (params.length > 0) {
			ParameterList pl = ct.getParameterList();
			if (pl == null) {
				return false;
			}
			for (int i=params.length-1; i >= 0; i--) {
				String v = pl.get(params[i][0]);
				if (v == null) {
					return false;
				}
				if (params[i][0].equals(CHARSET)) {
					v = v.toLowerCase(Locale.ENGLISH);
				}
				for (int k=params[i].length-1; k >= 0; k--) {
					String dst = params[i][k];
					if (dst.endsWith("*")) {
						if (v.startsWith(dst.substring(0, dst.length()-1))) {
							v = null;
							break;
						}
					} else if (dst.startsWith("*")) {
						if (v.endsWith(dst.substring(1))) {
							v = null;
							break;
						}
					} else if (v.equals(dst)) {
						v = null;
						break;
					}
				}
				if (v != null) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Normalize the given string for printing/logging by replacing all 
	 * TAB, CR, LF sqequences with a single space character.
	 * @param contentType	contenttype to normalize. Might be {@code null}.
	 * @return a normalized, possible empty string.
	 */
	public static final String normalize(String contentType) {
		return (contentType == null) 
			? "\"\""
			: contentType.toString().replaceAll("[\t\n\r]+", " ").trim();
	}

	/**
	 * Normalize the given string for printing/logging by replacing all 
	 * TAB, CR, LF sqequences with a single space character.
	 * @param contentType	contenttype to normalize. Might be {@code null}.
	 * @return a normalized, possible empty string.
	 */
	public static final String normalize(ContentType contentType) {
		return (contentType == null) ? "\"\"" : normalize(contentType.toString());
	}

	/**
	 * Convinience method to create a {@link ContentType} from a content type
	 * value string.
	 * 
	 * @param contenttype  content type value string to parse. If {@code null},
	 * 	{@code text/plain} will be used instead.
	 * @return {@code null} if the given string is not parsable, the content 
	 * 	type otherwise. 
	 */
	public static ContentType getContentType(String contenttype) {
		if (contenttype == null) {
			contenttype = "text/plain";
		}
		try {
			ContentType ct = new ContentType(contenttype);
			return ct;
		} catch (ParseException e) {
			log.warn("Invalid  content type '" + normalize(contenttype)
				+ "': " + e.getLocalizedMessage());
			if (log.isDebugEnabled()) {
				log.debug("getContentType()", e);
			}
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder();
		if (type.length == 0) {
			buf.append('*');
		} else {
			for (int i=0; i < type.length; i++) {
				buf.append(type[i]).append('|');
			}
			buf.setCharAt(buf.length()-1, '/');
		}
		if (subtype.length == 0) {
			buf.append('*');
		} else {
			for (int i=0; i < type.length; i++) {
				buf.append(subtype[i]).append('|');
			}
			buf.setLength(buf.length()-1);
		}
		for (int i=0; i < params.length; i++) {
			buf.append("; ").append(params[i][0]).append("=\"");
			for (int k=1; k < params[i].length; k++) {
				buf.append(params[i][k]).append('|');
			}
			buf.setCharAt(buf.length()-1, '"');
		}
		return buf.toString();
	}

	/**
	 * Tries to convert the given byte sequence into a string according to
	 * the content type's charset parameter.
	 * @param ct	content type to use. If {@code null}, UTF-8 decoding
	 * 	is assumed.
	 * @param content	bytes to convert.
	 * @return a possible empty string.
	 */
	public static String convert(ContentType ct, byte[] content) {
		Charset cs = null;
		if (ct != null) {
			String tmp = ct.getParameter("charset");
			if (tmp != null) {
				try {
					cs = Charset.forName(tmp);
				} catch (Exception e) {
					log.info(e.getLocalizedMessage());
				}
			}
		}
		if (cs == null) {
			cs = Charset.forName("UTF-8");
		}
		String s = new String(content, cs);
		return s;
	}

	/**
	 * Print out an example content type matcher expression.
	 * @param args	none
	 * @throws ParseException 
	 */
	public static void main(String[] args) throws ParseException {
		ContentTypeMatcher ctm = 
			new ContentTypeMatcher("*/plain|html;\n\tcharset=\"windows-1251\"");
		System.out.println(ctm.toString());
	}
}
