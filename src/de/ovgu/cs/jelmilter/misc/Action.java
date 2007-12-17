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
 * Type of action to be taken, if a rule set matches.
 * 
 * @author 	Jens Elkner
 * @version	$Revision$
 */
public enum Action {
	/** reject message */
	REJECT,
	/** discard message */
	DISCARD,
	/** accept message */
	ACCEPT,
	/** issue a temp fail response */
	TEMPFAIL
}
