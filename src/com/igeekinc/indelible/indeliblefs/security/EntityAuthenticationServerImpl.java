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
import java.rmi.RemoteException;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;

import sun.rmi.server.UnicastRef;

import com.igeekinc.indelible.oid.EntityID;

public class EntityAuthenticationServerImpl extends UnicastRemoteObject implements
        EntityAuthenticationServer
{
	private static final long serialVersionUID = -3388753119602325542L;
	EntityAuthenticationServerCore localServer;
	Logger logger = Logger.getLogger(getClass());;
	
    public EntityAuthenticationServerImpl(EntityAuthenticationServerCore localServer) throws RemoteException
    {
        this.localServer = localServer;
    }

    public EntityAuthenticationServerImpl(EntityAuthenticationServerCore localServer, int port) throws RemoteException
    {
        super(port);
        this.localServer = localServer;
    }

    public EntityAuthenticationServerImpl(EntityAuthenticationServerCore localServer, int port, RMIClientSocketFactory csf,
            RMIServerSocketFactory ssf) throws RemoteException
    {
        super(port, csf, ssf);
        this.localServer = localServer;
    }

    public int getServerPort()
    {
    	return ((UnicastRef)this.ref).getLiveRef().getPort();
    }
    
    public EntityAuthentication authenticateServer(EntityID serverID,
            byte [] certReq)
            throws CertificateEncodingException, InvalidKeyException,
            IllegalStateException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException,
            UnrecoverableKeyException, KeyStoreException, RemoteException,
            IOException, CertificateParsingException
    {
        return localServer.authenticateServer(serverID, certReq);
    }

    public EntityID getEntityID() throws RemoteException
    {
        return localServer.getEntityID();
    }

    public Certificate getServerCertificate() throws KeyStoreException,
            RemoteException
    {
        return localServer.getServerCertificate();
    }

    public void registerServer(X509Certificate selfSignedServerCert)
            throws InvalidKeyException, CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException, KeyStoreException, RemoteException
    {
        localServer.registerServer(selfSignedServerCert);
    }

    public byte[] entityAuthenticationServerChallenge(byte[] bytesToSign)
            throws RemoteException
    {
        return localServer.entityAuthenticationServerChallenge(bytesToSign);
    }
}
