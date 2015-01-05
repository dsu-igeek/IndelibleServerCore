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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import com.igeekinc.indelible.PreferencesManager;
import com.igeekinc.util.CheckCorrectDispatchThread;
import com.igeekinc.util.MonitoredProperties;
import com.igeekinc.util.SystemInfo;

public class IndelibleServerPreferences extends PreferencesManager
{
    public static final String kPropertiesFileName = "indelible.server.properties"; //$NON-NLS-1$
    public static final String kAutoInitEntityAuthenticationServerPropertyName = "indelible.server.properties.autoInitEntityAuthenticationServer";
    public static final String kEntityAuthenticationServerWasConfigured = "indelible.server.properties.entityAuthenticationServerWasConfigured";
    public static final String kLogFileDirectoryPropertyName = "indelible.server.LogFileDirectory"; //$NON-NLS-1$
    public static final String kRegistryPortPropertyName = "indelible.server.RegistryPort"; //$NON-NLS-1$
    public static final String kMoverPortPropertyName = "indelible.server.MoverPort";	//$NON-NLS-1$
    public static final String kLocalPortDirectory = "indelible.server.LocalPortDirectory";	//$NON-NLS-1$
	public static final String kServerPortPropertyName = "com.igeekinc.indelible.server.ServerPort";
    public static final String kIndelibleFSCASDBURLPropertyName = "indelible.server.properties.casDBURL";
    public static final String kIndelibleFSCASDBUserPropertyName = "indelible.server.properties.casDBUser";
    public static final String kIndelibleFSCASDBPasswordPropertyName = "indelible.server.properties.casDBPassword";
    public static final String kIndelibleFSCASDBStorageDirPropertyName = "indelible.server.properties.casStorageDir";
	public static final String kCreateVerboseLogFilesPropertyName = "com.igeekinc.indelible.client.createVerboseLogFiles"; //$NON-NLS-1$
	public static final String kVerboseLogFileLevelPropertyName = "com.igeekinc.indelible.client.VerboseLogFileLevel"; //$NON-NLS-1$
	public static final String kPurgeLogFilesAutomaticallyPropertyName = "com.igeekinc.indelible.client.PurgeLogFilesAutomatically"; //$NON-NLS-1$
	public static final String kDaysToRetainLogFilesPropertyName = "com.igeekinc.indelible.client.DaysToRetainLogFiles"; //$NON-NLS-1$
    public static final String kEnablePerformanceLogging = "com.igeekinc.indelible.server.EnablePerformanceLogging";	//$NON-NLS-1$
    public static final String kAdvertiseMoverAddressesPropertyName = "com.igeekinc.indelible.server.advertiseMoverAddresses";	//$NON-NLS-1$
	public static final String kPreferencesDirName = VendorProperties.getPropertyDirName();
    public static final String kLogDirName = "indelibleFSLogs";
    public static final String kJavaRMIServerHostname="java.rmi.server.hostname";

    public IndelibleServerPreferences(CheckCorrectDispatchThread dispatcher) throws IOException
    {
    	super(dispatcher);
    }
    
    public static void initPreferences(CheckCorrectDispatchThread dispatcher) throws IOException
    {
    	new IndelibleServerPreferences(dispatcher);	// This will automatically hook itself to the singleton
    }
    
    protected void initPreferencesInternal(CheckCorrectDispatchThread dispatcher)
    throws IOException
    {
        File preferencesDir = getPreferencesDir();
        Properties defaults = new Properties();
        defaults.setProperty(kLogFileDirectoryPropertyName, new File(SystemInfo.getSystemInfo().getLogDirectory(), kLogDirName).getAbsolutePath()); //$NON-NLS-1$
        defaults.setProperty(kMoverPortPropertyName, "50903");
        File localSocketDefault = new File(SystemInfo.getSystemInfo().getTemporaryDirectory(), "indelible-fs");
        defaults.setProperty(kLocalPortDirectory, localSocketDefault.getAbsolutePath());
        properties = new MonitoredProperties(defaults, dispatcher);
        setIfNotSet(kPreferencesDirPropertyName, preferencesDir.getAbsolutePath()); //$NON-NLS-1$
        setIfNotSet(kIndelibleFSCASDBURLPropertyName, "jdbc:postgresql://localhost/castest");
        setIfNotSet(kIndelibleFSCASDBUserPropertyName, "indelible");
        setIfNotSet(kIndelibleFSCASDBPasswordPropertyName, "indeliblefs");
        setIfNotSet(kAutoInitEntityAuthenticationServerPropertyName, "Y");
        setIfNotSet(kEntityAuthenticationServerWasConfigured, "N");
        File propertiesFile = getPreferencesFile(); //$NON-NLS-1$
        if (propertiesFile.exists())
        {
            FileInputStream propertiesInputStream = new FileInputStream(propertiesFile);
            properties.load(propertiesInputStream);
            propertiesInputStream.close();
        }
        
        storeProperties();
    }

	public File getPreferencesFileInternal()
	{
		File preferencesDir = getPreferencesDirInternal();
		return new File(preferencesDir, kPropertiesFileName);
	}

	public File getPreferencesDirInternal()
	{
		return new File(SystemInfo.getSystemInfo().getGlobalPreferencesDirectory(), kPreferencesDirName);
	}
}
