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
 
package com.igeekinc.indelible.indeliblefs.security;

import java.io.IOException;
import java.io.Serializable;
import java.net.ServerSocket;
import java.rmi.server.RMIServerSocketFactory;
import java.security.GeneralSecurityException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import org.apache.log4j.Logger;

import com.igeekinc.indelible.oid.EntityID;
import com.igeekinc.util.logging.ErrorLogMessage;

public class IndelibleEntityAuthenticationClientRMIServerSocketFactory implements RMIServerSocketFactory, Serializable
{

    private static final long serialVersionUID = 6256087609695722472L;

    private EntityID entityAuthenticationServerID;
    private transient Logger logger;
    
    public IndelibleEntityAuthenticationClientRMIServerSocketFactory(EntityID securityServerID)
    {
        this.entityAuthenticationServerID = securityServerID;
    }
    
    public ServerSocket createServerSocket(int port) throws IOException
    {
        try
        {
            SSLContext sslContext = SSLContext.getInstance("TLS");


            sslContext.init(EntityAuthenticationClient.getEntityAuthenticationClient().getKeyManagers(entityAuthenticationServerID), EntityAuthenticationClient.getEntityAuthenticationClient().getTrustManagers(entityAuthenticationServerID), null);
            SSLServerSocketFactory socketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) socketFactory.createServerSocket(port);
            serverSocket.setNeedClientAuth(true);
            if (logger == null)
            	logger = Logger.getLogger(getClass());
            logger.debug("Created SSLServerSocket on port "+serverSocket.getLocalPort()+" SecurityServerID = "+entityAuthenticationServerID);
            return serverSocket;
        } catch (GeneralSecurityException e)
        {
            logger.error(new ErrorLogMessage("Caught exception"), e);
            throw new IOException("Could not create server socket due to security exception", e);
        }
    }
}
