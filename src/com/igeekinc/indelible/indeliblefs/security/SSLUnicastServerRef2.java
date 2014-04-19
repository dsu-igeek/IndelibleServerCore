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
import java.lang.reflect.Field;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.RemoteCall;

import javax.net.ssl.SSLSocket;

import org.apache.log4j.Logger;

import sun.rmi.server.UnicastServerRef2;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.StreamRemoteCall;
import sun.rmi.transport.tcp.TCPConnection;

import com.igeekinc.indelible.oid.EntityID;
import com.igeekinc.util.logging.ErrorLogMessage;

@SuppressWarnings("deprecation")
public class SSLUnicastServerRef2 extends UnicastServerRef2
{
    ThreadLocal<EntityAuthentication>clientEntityAuthenticationForThread = new ThreadLocal<EntityAuthentication>();
    ThreadLocal<EntityAuthentication>serverEntityAuthenticationForThread = new ThreadLocal<EntityAuthentication>();
    public SSLUnicastServerRef2()
    {
        super();
    }

    public SSLUnicastServerRef2(int port, RMIClientSocketFactory csf,
            RMIServerSocketFactory ssf)
    {
        super(port, csf, ssf);
    }

    public SSLUnicastServerRef2(LiveRef ref)
    {
        super(ref);
    }

    @Override
    public void dispatch(Remote obj, RemoteCall call) throws IOException
    {
        StreamRemoteCall src = (StreamRemoteCall)call;
        TCPConnection tcpConnection = (TCPConnection)src.getConnection();
        try
        {
            Field socketField = TCPConnection.class.getDeclaredField("socket");
            socketField.setAccessible(true);
            SSLSocket socket = (SSLSocket) socketField.get(tcpConnection);
            EntityAuthentication authenticatedClientID = EntityAuthenticationClient.getEntityAuthenticationClient().getClientEntityAuthenticationForSocket(socket);
            clientEntityAuthenticationForThread.set(authenticatedClientID);
            
            EntityAuthentication authenticatedServerID = EntityAuthenticationClient.getEntityAuthenticationClient().getServerEntityAuthenticationForSocket(socket);
            serverEntityAuthenticationForThread.set(authenticatedServerID);
        } catch (SecurityException e)
        {
            Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
            throw new RemoteException("SecurityException", e);
        } catch (NoSuchFieldException e)
        {
            Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
            throw new RemoteException("NoSuchFieldException", e);
        } catch (IllegalArgumentException e)
        {
            Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
            throw new RemoteException("IllegalArgumentException", e);
        } catch (IllegalAccessException e)
        {
            Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
            throw new RemoteException("IllegalAccessException", e);
        } catch (AuthenticationFailureException e)
        {
            Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
            throw new RemoteException("Authentication failed", e);
        }
        
        super.dispatch(obj, call);
    }
    
    public EntityID getEntityIDForThread()
    {
        return clientEntityAuthenticationForThread.get().getEntityID();
    }
    
    public EntityAuthentication getClientEntityAuthenticationForThread()
    {
    	return clientEntityAuthenticationForThread.get();
    }
    
    public EntityAuthentication getServerEntityAuthenticationForThread()
    {
    	return serverEntityAuthenticationForThread.get();
    }
}
