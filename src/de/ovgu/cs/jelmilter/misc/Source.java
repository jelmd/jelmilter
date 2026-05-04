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
