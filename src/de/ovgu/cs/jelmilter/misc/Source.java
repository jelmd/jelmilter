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

/**
 * Source of information to scan.
 * 
 * @author 	Jens Elkner
 * @version	$Revision$
 */
public enum Source {
	/** MAIL FROM: related arguments */
	MAIL_FROM,
	/** RCPT TO: related arguments */
	RCPT_TO,
	/** HEADER fields and values */
	HEADER,
	/** mail body */
	BODY
}
