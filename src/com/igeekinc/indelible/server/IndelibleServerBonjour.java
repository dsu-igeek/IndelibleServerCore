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

import java.lang.reflect.Constructor;

import org.apache.log4j.Logger;

import com.igeekinc.util.MonitoredProperties;
import com.igeekinc.util.OSType;
import com.igeekinc.util.SystemInfo;
import com.igeekinc.util.logging.WarnLogMessage;

public abstract class IndelibleServerBonjour
{
	protected IndelibleServer parent;
    protected Logger logger = Logger.getLogger(getClass());
    protected MonitoredProperties serverProperties;
    protected boolean advertise = false;
    public static IndelibleServerBonjour getIndelibleServerBonjour(IndelibleServer parent)
    {
    	String  osName = System.getProperty("os.name"); //$NON-NLS-1$
		String className = null;
		IndelibleServerBonjour singleton = null;
			
		if (SystemInfo.getSystemInfo().getOSType() == OSType.kWindows) //$NON-NLS-1$
		{
			className = "com.igeekinc.indelible.server.windows.IndelibleServerBonjourWindows"; //$NON-NLS-1$
		}
		
		if (SystemInfo.getSystemInfo().getOSType() == OSType.kMacOSX) //$NON-NLS-1$
		{
			className = "com.igeekinc.indelible.server.macosx.IndelibleServerBonjourMacOSX"; //$NON-NLS-1$
		}
		
		if (SystemInfo.getSystemInfo().getOSType() ==  OSType.kLinux) //$NON-NLS-1$
		{
			className = "com.igeekinc.indelible.server.linux.IndelibleServerBonjourLinux";	//$NON-NLS-1$
		}
		if (className == null)
			throw new InternalError("System type "+osName+" is unknown"); //$NON-NLS-1$ //$NON-NLS-2$
		try
		{
			Class<? extends IndelibleServerBonjour> fsClientClass = (Class<? extends IndelibleServerBonjour>) Class.forName(className);

			Class<?> [] constructorArgClasses = {IndelibleServer.class};
			Constructor<? extends IndelibleServerBonjour> fsClientConstructor = fsClientClass.getConstructor(constructorArgClasses);
			Object [] constructorArgs = {parent};
			singleton = fsClientConstructor.newInstance(constructorArgs);
		}
		catch (Throwable t)
		{
			Logger.getLogger(IndelibleServerBonjour.class).error("Caught exception creating IndelibleServerBonjour", t); //$NON-NLS-1$
		}
		return singleton;
    }
    
    public IndelibleServerBonjour(IndelibleServer parent)
    {
    	this.parent = parent;
    }
    
    public void setServerProperties(MonitoredProperties serverProperties)
    {
    	this.serverProperties = serverProperties;
    	if (serverProperties.getProperty("indelible.server.advertise", "N").equals("Y"))
    	{
    		advertise = true;
    		logger.warn(new WarnLogMessage("Bonjour advertising is enabled"));
    	}
    	else
    	{
    		advertise = false;
    		logger.warn(new WarnLogMessage("Bonjour advertising is disabled"));
    	}
    }
    public abstract void advertiseEntityAuthenticationServer(int entityAuthenticationPort) throws Exception;
	public abstract void advertiseRegistry(int registryPort) throws Exception;

}
