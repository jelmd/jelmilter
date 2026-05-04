/**
 * Copyright (c) 2005-2005 Jens Elkner.
 * All Rights Reserved.
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package de.ovgu.cs.jelmilter;

/**
 * Get the version of the package.
 *
 * @author Jens Elkner
 * @version 1.0
 */
public class Version {

	/** stuff will be replaced by ant */
	private static final String productName = "@product.name@";
	private static final String productVersion = "@product.version@";
	private static final String yearStart = "@year.start@";
	private static final String yearEnd = "@year.end@";
	private static final String vendorName = "@vendor.name@";
	private static final String vendorURL = "@vendor.url@";
	private static final String buildNumber = "@build.number@";
	
	/**
	 * Get the offical name of this product
	 * @return this product's name
	 */
	public String getProductName() {
		return productName;
	}

	/**
	 * Get the version of this product (usually a major.minor.tiny version number)
	 * @return this products version
	 */
	public String getProductVersion() {
		return productVersion;
	}

	/**
	 * The build number of this version (usully the revision of the commited
	 * svn version).
	 * @return a build number
	 */
	public String getBuildNumber() {
		return buildNumber;
	}
	
	/**
	 * Get the year, when the development of this application started.
	 * @return year of project start
	 */
	public String getFromYear() {
		return yearStart;
	}

	/**
	 * Get the year, when this application was last modified.
	 * @return year of last modification
	 */
	public String getEndYear() {
		return yearEnd;
	}

	/**
	 * Get the name of the vendor
	 * @return the vendor name
	 */
	public String getVendorName() {
		return vendorName;
	}

	/**
	 * Get the URL of the product vendor
	 * @return the vendor URL
	 */
	public String getVendorURL() {
		return vendorURL;
	}

	/**
	 * Get the complete version info for this application
	 * @return multilined version info 
	 */
	public String getVersionInfo() {
		String eol = System.getProperty("line.separator");
		String year = yearStart.equals(yearEnd) 
			? yearStart
			: yearStart + " - " + yearEnd;
		return eol + productName + "  " + productVersion 
			+ " (" + buildNumber + ")" + eol
			+ "Copyright (C) " + year + "  " + vendorName + eol
			+ vendorURL + eol;
	}

	/**
	 * Get the path to the license file.
	 * @return a hardcoded path wrt. to a jar file
	 */
	public String getLicensePath() {
        return Version.class.getPackage().getName().replaceAll("\\.","/") 
        	+ "/res/license.txt";
	}
	
	/**
	 * Print the version/copyright/vendor information for this package.
	 *
	 * @param args  none
	 */
	public static void main(String[] args) {
		System.out.println((new Version()).getVersionInfo());
	}
}
