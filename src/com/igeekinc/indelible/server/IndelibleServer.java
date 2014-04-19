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
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.UnknownHostException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;

import org.apache.log4j.DailyRollingFileAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.PropertyConfigurator;
import org.perf4j.log4j.AsyncCoalescingStatisticsAppender;

import sun.rmi.registry.RegistryImpl;
import sun.rmi.server.UnicastServerRef;

import com.igeekinc.indelible.indeliblefs.IndelibleEntity;
import com.igeekinc.indelible.indeliblefs.security.AuthenticationFailureException;
import com.igeekinc.indelible.indeliblefs.security.EntityAuthenticationClient;
import com.igeekinc.indelible.indeliblefs.security.EntityAuthenticationClientListener;
import com.igeekinc.indelible.indeliblefs.security.EntityAuthenticationFirehoseServer;
import com.igeekinc.indelible.indeliblefs.security.EntityAuthenticationServer;
import com.igeekinc.indelible.indeliblefs.security.EntityAuthenticationServerAppearedEvent;
import com.igeekinc.indelible.indeliblefs.security.EntityAuthenticationServerCore;
import com.igeekinc.indelible.indeliblefs.security.EntityAuthenticationServerDisappearedEvent;
import com.igeekinc.indelible.indeliblefs.security.EntityAuthenticationServerFirehoseClient;
import com.igeekinc.indelible.indeliblefs.security.EntityAuthenticationServerTrustedEvent;
import com.igeekinc.indelible.indeliblefs.security.EntityAuthenticationServerUntrustedEvent;
import com.igeekinc.indelible.oid.EntityID;
import com.igeekinc.indelible.oid.ObjectIDFactory;
import com.igeekinc.util.MonitoredProperties;
import com.igeekinc.util.logging.ErrorLogMessage;
import com.igeekinc.util.logging.FatalLogMessage;
import com.igeekinc.util.logging.InfoLogMessage;

public abstract class IndelibleServer implements EntityAuthenticationClientListener
{

    public static long kWaitForOtherSecurityServersDelay = 30000;
    protected Logger logger;
    protected IndelibleServerBonjour bonjour;
    protected EntityAuthenticationServer entityAuthenticationServer;
    protected EntityAuthenticationFirehoseServer entityAuthenticationFirehoseServer;
    protected DailyRollingFileAppender rollingLog;
    protected DailyRollingFileAppender statsLog, rawLog;	// These are the log files for performance statistics
    protected Registry serverRegistry;
	protected MonitoredProperties serverProperties;
    
    public IndelibleServer()
    {
        logger = Logger.getLogger(this.getClass());
    	bonjour = IndelibleServerBonjour.getIndelibleServerBonjour(this);

    }

    protected abstract boolean shouldCreateRegistry();
    
    public void setServerProperties(MonitoredProperties serverProperties)
    {
    	this.serverProperties = serverProperties;
    	// It's nice to be able to set java.rmi.server.hostname in the server preferences rather than on the command line
    	if (serverProperties.containsKey(IndelibleServerPreferences.kJavaRMIServerHostname))
    		System.getProperties().setProperty(IndelibleServerPreferences.kJavaRMIServerHostname, 
    				serverProperties.getProperty(IndelibleServerPreferences.kJavaRMIServerHostname));
    	if (shouldCreateRegistry())
    	{
    		String serverPortStr = serverProperties.getProperty(IndelibleServerPreferences.kServerPortPropertyName);
    		int serverPort = 0;	// Random port
    		if (serverPortStr != null)
    		{
    			serverPort = Integer.parseInt(serverPortStr);
    		}
    		try
    		{
    			createRegistry(serverPort);
    		} catch (Exception e)
    		{
    			// TODO Auto-generated catch block
    			e.printStackTrace();
    		}
    		if (bonjour != null)
    		{
    			bonjour.setServerProperties(serverProperties);
    			try
    			{
    				bonjour.advertiseRegistry(serverPort);
    			} catch (Exception e)
    			{
    				// TODO Auto-generated catch block
    				Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
    			}
    		}
    	}
    }
    public EntityAuthenticationServer getLocalSecurityServer()
    {
        return entityAuthenticationServer;
    }

    /**
     * 
     */
    protected void configureLogging(MonitoredProperties serverProperties)
    {
        Properties loggingProperties = new Properties();
        loggingProperties.putAll(serverProperties);
        File additionalLoggingConfigFile = new File(serverProperties.getProperty(IndelibleServerPreferences.kPreferencesDirPropertyName),
        "executorLoggingOptions.properties"); //$NON-NLS-1$
        Exception savedException = null;
        try
        {
            if (additionalLoggingConfigFile.exists())
            {
                Properties additionalLoggingProperties = new Properties();
                FileInputStream additionalLoggingInStream = new FileInputStream(additionalLoggingConfigFile);
                additionalLoggingProperties.load(additionalLoggingInStream);
                loggingProperties.putAll(additionalLoggingProperties);
            }	
        }
        catch (Exception e)
        {
            savedException = e;
        }
        Logger.getRootLogger().removeAllAppenders();	// Clean up anything lying around
        PropertyConfigurator.configure(loggingProperties);
        rollingLog = new DailyRollingFileAppender();
    
        File logDir = new File(getLogFileDir()); //$NON-NLS-1$
        logDir.mkdirs();
        File logFile = new File(logDir, getServerLogFileName()); //$NON-NLS-1$
        System.out.println("Server log file = "+logFile.getAbsolutePath());
        String logFileEncoding = VendorProperties.getLogFileEncoding();
    	if (logFile.exists() && logFileEncoding.toLowerCase().equals("utf-16") && logFile.length() >= 2)
    	{
    		SimpleDateFormat checkFormatter = new SimpleDateFormat("yyyy-MM-dd");
    		if (checkFormatter.format(new Date()).equals(checkFormatter.format(new Date(logFile.lastModified()))))	// We'll be writing to the same file
    		{
    			// Check the BOM
    			try {
    				InputStream checkStream = new FileInputStream(logFile);
    				int bom0 = checkStream.read();
    				int bom1 = checkStream.read();
    				if (bom0 == 0xfe && bom1 == 0xff)
    					logFileEncoding = "utf-16be";
    				else
    					logFileEncoding = "utf-16le";
    			} catch (FileNotFoundException e) {
    				// TODO Auto-generated catch block
    				e.printStackTrace();
    			} catch (IOException e) {
    				// TODO Auto-generated catch block
    				e.printStackTrace();
    			}
    		}
    	}
        rollingLog.setEncoding(logFileEncoding);
        rollingLog.setFile(logFile.getAbsolutePath());
        rollingLog.setDatePattern("'.'yyyy-MM-dd"); //$NON-NLS-1$
        setLogFileLevelFromPrefs();
    
        rollingLog.activateOptions();
        //rollingLog.setLayout(new XMLLayout());
        rollingLog.setLayout(new PatternLayout("%d %-5p [%t]: %m%n")); //$NON-NLS-1$
        Logger.getRootLogger().addAppender(rollingLog);
    
        if (savedException != null)
            logger.error("Caught exception reading loggingOptions.properties file", savedException); //$NON-NLS-1$
    	Logger timingLogger = Logger.getLogger("org.perf4j.TimingLogger");
    	timingLogger.setLevel(Level.INFO);
    	timingLogger.setAdditivity(false);
        if (serverProperties.getProperty(IndelibleServerPreferences.kEnablePerformanceLogging, "N").toUpperCase().equals("Y"))
        {
        	try
			{
				File statsLogFile = new File(logDir, getServerStatsLogFileName()); //$NON-NLS-1$
				statsLog = new DailyRollingFileAppender(new PatternLayout("%m%n"), statsLogFile.getAbsolutePath(), "'.'yyyy-MM-dd");
				File rawLogFile = new File(logDir, getServerRawPerfLogFileName());
				rawLog = new DailyRollingFileAppender(new PatternLayout("%m%n"), rawLogFile.getAbsolutePath(), "'.'yyyy-MM-dd");
				AsyncCoalescingStatisticsAppender statsAppender = new AsyncCoalescingStatisticsAppender();
		    	statsAppender.setName("statsAppender");
		    	statsAppender.setTimeSlice(10000);
		    	statsAppender.addAppender(statsLog);
		    	statsAppender.activateOptions();

		    	timingLogger.addAppender(statsAppender);
		    	timingLogger.addAppender(rawLog);
			} catch (IOException e)
			{
				// TODO Auto-generated catch block
				Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
			}

        }
        setupPropertiesListener();
    }

	public abstract void setupPropertiesListener();
	/*
	{
		IndelibleServerPreferences.getProperties().addPropertyChangeListener(new PropertyChangeListener(){
            public void propertyChange(java.beans.PropertyChangeEvent evt) {
                setLogFileLevelFromPrefs();
            };
        });
	}
*/
    public abstract String getServerLogFileName();

    public String getServerStatsLogFileName()
    {
    	return getServerLogFileName()+".stats";
    }
    public String getServerRawPerfLogFileName()
    {
    	return getServerLogFileName()+".raw";
    }
    public abstract String getLogFileDir();
    
    public abstract void setLogFileLevelFromPrefs();
    /*
    private void setLogFileLevelFromPrefs()
    {
        if (IndelibleServerPreferences.getProperties().getProperty(IndelibleServerPreferences.kCreateVerboseLogFilesPropertyName, "N").equals("N")) //$NON-NLS-1$ //$NON-NLS-2$
            rollingLog.setThreshold(Level.INFO);
        else
            rollingLog.setThreshold(Level.toLevel(IndelibleServerPreferences.getProperties().getProperty(IndelibleServerPreferences.kVerboseLogFileLevelPropertyName, "INFO"), Level.INFO)); //$NON-NLS-1$
    }
    */
    protected abstract void storeProperties() throws IOException;
    
    protected abstract void setEntityAuthenticationServerConfiguredProperty();
    
    protected abstract boolean shouldAutoInitEntityAuthenticationServer();

    protected abstract boolean entityAuthenticationServerWasConfigured();

    protected void autoConfigureSecurityServer(File securityRootDir, ObjectIDFactory objectIDFactory)
            throws KeyStoreException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException,
            CertificateException, FileNotFoundException, IOException
    {
        if (!entityAuthenticationServerWasConfigured())
        {
    
            if (shouldAutoInitEntityAuthenticationServer())
            {
    
                // Is there anybody out there?  If we're set to auto-configure, first check to see if someone else is the security root
                long startTime = System.currentTimeMillis();
                boolean foundOtherSecurityServer = false;
                while (!foundOtherSecurityServer && System.currentTimeMillis() - startTime < kWaitForOtherSecurityServersDelay)
                {
                    EntityAuthenticationServer [] securityServers = EntityAuthenticationClient.listEntityAuthenticationServers();
                    if (securityServers.length == 0)
                    {
                        try
                        {
                            Thread.sleep(10000);
                        } catch (InterruptedException e)
                        {
                            Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
                        }
                    }
                    else
                    {
                        if (securityServers.length > 1)
                        {
                            // Need to check for security domains later
                            logger.fatal(new FatalLogMessage("Multiple security servers are present.  Cannot auto-configure"));
                            System.exit(-1);
                        }
                        foundOtherSecurityServer = true;
                        entityAuthenticationServer = securityServers[0];
                    }
                }
    
                if (!foundOtherSecurityServer)
                {
                    initializeSecurityServerInfo(securityRootDir, objectIDFactory);
                }
            }
            else
            {
                // Not configured and we can't configure auto-magically.  Bail
                logger.fatal("Security server is not configured and system is not set for auto-configure - exiting");
                System.exit(-1);
            }
        }
    }

    protected void initializeSecurityServerInfo(File securityRootDir,
            ObjectIDFactory objectIDFactory) throws KeyStoreException,
            NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException, CertificateException,
            FileNotFoundException, IOException
    {
        if (securityRootDir.exists())
        {
            if (securityRootDir.isDirectory())
            {
                if (securityRootDir.list(new FilenameFilter() {
                    public boolean accept(File arg0, String arg1)
                    {
                        if (arg1.startsWith("."))
                            return false;
                        return true;
                    }
                }).length > 0)
                {
                    logger.fatal("Security root dir "+securityRootDir.getAbsolutePath()+" exists but we are not configured to use it - exiting");
                    System.exit(-1);
                }
                else
                {
                    securityRootDir.delete();
                }
            }
            else
            {
                logger.fatal("Security root dir "+securityRootDir.getAbsolutePath()+" exists but is not a directory - exiting");
                System.exit(-1);
            }
        }
        if (securityRootDir.mkdir())
        {
            EntityAuthenticationServerCore.initRootSecurity(securityRootDir, (EntityID)objectIDFactory.getNewOID(IndelibleEntity.class));
        }
        else
        {
            logger.fatal("Could not create security root dir "+securityRootDir.getAbsolutePath());
            System.exit(-1);
        }
        setEntityAuthenticationServerConfiguredProperty();
        storeProperties();
    }

    protected void configureEntityAuthenticationClient(File entityAuthenticationClientKeystoreFile, EntityID serverID, ObjectIDFactory objectIDFactory, MonitoredProperties properties)
            throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, IOException,
            UnrecoverableKeyException, InvalidKeyException,
            NoSuchProviderException, SignatureException, RemoteException
    {
        // Now, check and configure the security client
        
        if (!entityAuthenticationClientKeystoreFile.exists())
        {
            if (shouldAutoInitEntityAuthenticationServer() && entityAuthenticationServer != null)
            {
                // We're supposed to auto init...If entityAuthenticationServer is set then we can just use that (it's either our server in this
                // JVM or the only entity authentication server found on the net.  If it's not set, then we need to bail
                EntityAuthenticationClient.initIdentity(entityAuthenticationClientKeystoreFile, serverID, entityAuthenticationServer.getServerCertificate());
            }
            else
            {
                // Not initialized and we're not supposed to do it automatically - just exit
                logger.fatal(new FatalLogMessage("No security server configured and auto configure is disabled, exiting"));
                System.exit(-1);
            }
        }
        try
        {
            EntityAuthenticationClient.initializeEntityAuthenticationClient(entityAuthenticationClientKeystoreFile, objectIDFactory, properties);
            EntityAuthenticationClient.getEntityAuthenticationClient().addEntityAuthenticationClientListener(this);
        } catch (AuthenticationFailureException e)
        {
            Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
            System.exit(-1);
        }
    }

    public void entityAuthenticationServerAppeared(EntityAuthenticationServerAppearedEvent addedEvent)
    {
    	EntityAuthenticationServer addedServer = addedEvent.getAddedServer();
        EntityAuthenticationClient.getEntityAuthenticationClient().trustServer(addedServer);
    }

    public void entityAuthenticationServerDisappeared(
            EntityAuthenticationServerDisappearedEvent removedEvent)
    {
        // TODO Auto-generated method stub
        
    }

    
    public void entityAuthenticationServerTrusted(EntityAuthenticationServerTrustedEvent trustedEvent)
    {
        try
        {
            EntityID securityServerID = trustedEvent.getAddedServer().getEntityID();

        } catch (Exception e)
        {
            Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
        }
    }

    public void entityAuthenticationServerUntrusted(EntityAuthenticationServerUntrustedEvent untrustedEvent)
    {
        // TODO Auto-generated method stub
        
    }

    private void createRegistry(int portNumber) throws Exception
    {
        Registry registry = serverRegistry;
        if (registry == null)
        {
            registry = LocateRegistry.createRegistry(portNumber);
            try {
				String localHostMessage = "localhost addr = "+java.net.InetAddress.getLocalHost();
				logger.info(localHostMessage);
				String rmiServerHostname = System.getProperty("java.rmi.server.hostname");
				logger.info(new InfoLogMessage("Creating registry, java.rmi.server.hostname={0}", new Serializable[]{rmiServerHostname}));
			} catch (UnknownHostException e) {
				
			}
            int registryPort = ((UnicastServerRef)((RegistryImpl)registry).getRef()).getLiveRef().getPort();
            if (bonjour != null)
            	bonjour.advertiseRegistry(registryPort);
            logger.error(new ErrorLogMessage("IndelibleServer registry starting on port {0}", new Serializable[]{registryPort}));
            serverRegistry = registry;
        }
    }


}
