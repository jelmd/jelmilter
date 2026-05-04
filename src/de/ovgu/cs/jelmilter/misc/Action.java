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
