/*
 * Copyright 2002-2014 iGeek, Inc.
 * All Rights Reserved
 * @Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.@
 */
 
package com.igeekinc.indelible.server;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import javax.swing.ImageIcon;

public class VendorProperties {

	private static final String kBundleName = "com.igeekinc.indelible.client.vendor.vendor"; //$NON-NLS-1$
	private static final String kLocalizableBundleName = "com.igeekinc.indelible.client.vendor.vendor-localizable"; //$NON-NLS-1$
	private static final ResourceBundle kResourceBundle =
		ResourceBundle.getBundle(kBundleName);
	private static final ResourceBundle kLocalizableResourceBundle = ResourceBundle.getBundle(kLocalizableBundleName);
	public static final String kPropertyDirName="com.igeekinc.indelible.propertyDirName"; //$NON-NLS-1$
	public static final String kLogDirName="com.igeekinc.indelible.logDirName"; //$NON-NLS-1$
	public static final String kMajorPropertyName="com.igeekinc.indelible.major"; //$NON-NLS-1$
	public static final String kMinorPropertyName="com.igeekinc.indelible.minor"; //$NON-NLS-1$
	public static final String kPointPropertyName="com.igeekinc.indelible.point"; //$NON-NLS-1$
	public static final String kAppNamePropertyName="com.igeekinc.indelible.name"; //$NON-NLS-1$
	public static final String kVendorNamePropertyName="com.igeekinc.indelible.vendorName"; //$NON-NLS-1$
	public static final String kUpdateURLPropertyName="com.igeekinc.indelible.updateURL"; //$NON-NLS-1$
	public static final String kPurchaseURLPropertyName="com.igeekinc.indelible.purchaseURL"; //$NON-NLS-1$
	public static final String kUILogFileNamePropertyName="com.igeekinc.indelible.uiLogFileName"; //$NON-NLS-1$
	public static final String kLogFileEncodingPropertyName="com.igeekinc.indelible.logFileEncoding"; //$NON-NLS-1$
	public static final String kUpdatePropertiesURLName="com.igeekinc.indelible.updatePropertiesURL"; //$NON-NLS-1$
	public static final String kTrialExpiredTextName="com.igeekinc.indelible.trialExpiredText"; //$NON-NLS-1$
	public static final String kValidRegCodeClasses="com.igeekinc.indelible.validRegCodeClasses"; //$NON-NLS-1$
    public static final String kUpgradeableRegCodeClasses = "com.igeekinc.indelible.upgradeableRegCodeClasses"; //$NON-NLS-1$
    public static final String kAppDirNamePropertyName="com.igeekinc.indelible.appDirName"; //$NON-NLS-1$
    public static final String kGUIAppNamePropertyName="com.igeekinc.indelible.guiAppName"; //$NON-NLS-1$
    public static final String kSplashScreenResourceNamePropertyName = "com.igeekinc.indelible.splashScreenResourceName";
    public static final String kAboutBoxResourceNamePropertyName = "com.igeekinc.indelible.aboutBoxResourceName";
    /**
	 * 
	 */
	private VendorProperties() {

		// TODO Auto-generated constructor stub
	}
	/**
	 * @param key
	 * @return
	 */
	public static String getString(String key) 
	{
		try 
		{
			return kResourceBundle.getString(key);
		} 
		catch (MissingResourceException e) 
		{
		    try
		    {
		        return kLocalizableResourceBundle.getString(key);
		    }
		    catch (MissingResourceException e1)
		    {
		        return '!' + key + '!';
		    }
		}
	}
	
	public static String getMajorVersion()
	{
	    return(getString(kMajorPropertyName));
	}
	
	public static String getMinorVersion()
	{
	    return(getString(kMinorPropertyName));
	}
	
	public static String getPointVersion()
	{
	    return(getString(kPointPropertyName));
	}
	
	public static String getVersionString()
	{
		return(getString(kMajorPropertyName)+"."+getString(kMinorPropertyName)+ //$NON-NLS-1$
				"."+getString(kPointPropertyName)); //$NON-NLS-1$
	}
	
	public static String getAppNameString()
	{
		return(getString(kAppNamePropertyName)+" "+getVersionString()); //$NON-NLS-1$
	}
	
	public static String getAppTitle()
	{
		return(getString(kAppNamePropertyName));
	}
	
	public static String getVendorName()
	{
		return(getString(kVendorNamePropertyName));
	}
	
	public static String getSplashScreenResourceName()
	{
		return(getString(kSplashScreenResourceNamePropertyName));
	}
	
	public static String getAboutBoxResourceName()
	{
		return(getString(kAboutBoxResourceNamePropertyName));
	}
	
	public static ImageIcon getSplashScreenImage(){
		String imagePathName = getSplashScreenResourceName();
	    if (imagePathName == null)
	      return null;
	    URL imageURL = ClassLoader.getSystemClassLoader().getResource(imagePathName);
	    ImageIcon returnIcon = new ImageIcon(imageURL);
	    return(returnIcon);
	}
	
	public static ImageIcon getAboutBoxImage(){
		String imagePathName = getAboutBoxResourceName();
	    if (imagePathName == null)
	      return null;
	    URL imageURL = ClassLoader.getSystemClassLoader().getResource(imagePathName);
	    ImageIcon returnIcon = new ImageIcon(imageURL);
	    return(returnIcon);
	}
	
	public static URL getUpdateURL()
	throws MalformedURLException
	{
		return(new URL(getString(kUpdateURLPropertyName)));
	}
	
	public static URL getPurchaseURL()
	throws MalformedURLException
	{
		return(new URL(getString(kPurchaseURLPropertyName)));
	}
	
	public static String getPropertyDirName()
	{
		return(getString(kPropertyDirName));
	}
	/**
	 * @return
	 */
	public static String getUILogFileName()
	{
		return(getString(kUILogFileNamePropertyName));
	}
	
	public static String getLogFileEncoding()
	{
		try 
		{
			return kResourceBundle.getString(kLogFileEncodingPropertyName);
		} 
		catch (MissingResourceException e) 
		{
			return("utf-8"); //$NON-NLS-1$
		}
	}
    /**
     * @return
     */
    public static URL getUpdatePropertiesURL()
    throws MalformedURLException
    {
        return new URL(getString(kUpdatePropertiesURLName));
    }
    
    public static String getTrialExpiredText()
    {
        return(getString(kTrialExpiredTextName));
    }
    
    public static String getGUIAppName()
    {
        return(getString(kGUIAppNamePropertyName));
    }
}
