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
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.newsclub.net.unix.AFUNIXSocketAddress;

import com.igeekinc.firehose.AddressFilter;
import com.igeekinc.indelible.indeliblefs.IndelibleEntity;
import com.igeekinc.indelible.oid.EntityID;
import com.igeekinc.indelible.oid.GeneratorID;
import com.igeekinc.indelible.oid.GeneratorIDFactory;
import com.igeekinc.indelible.oid.IndelibleFSClientOIDs;
import com.igeekinc.indelible.oid.ObjectIDFactory;
import com.igeekinc.junitext.iGeekTestCase;
import com.igeekinc.util.logging.ErrorLogMessage;



public class EntityAuthenticationServerNewRMITest extends iGeekTestCase
{
	static EntityAuthenticationServerCore core;
	static EntityAuthenticationFirehoseServer tcpServer, afUnixServer;
	static EntityID id;
	static KeyPair	keyPair;
	static AFUNIXSocketAddress afUnixServerAddress;
	
	static
	{
		try
		{
			IndelibleFSClientOIDs.initMappings();
			Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 2);
			GeneratorIDFactory myGenIDFactory = new GeneratorIDFactory();
			GeneratorID myGenID = myGenIDFactory.createGeneratorID();
			ObjectIDFactory testFactory = new ObjectIDFactory(myGenID);
			File securityRootDir = File.createTempFile("EntityAuthenticationServerNewRMITest", ".dir");
			securityRootDir.delete();
			assertTrue(securityRootDir.mkdir());
			EntityAuthenticationServerCore.initRootSecurity(securityRootDir, (EntityID)testFactory.getNewOID(EntityAuthenticationServerCore.class));
			id = (EntityID) testFactory.getNewOID(IndelibleEntity.class);
			core = new EntityAuthenticationServerCore(securityRootDir);
			tcpServer = new EntityAuthenticationFirehoseServer(core, new InetSocketAddress(0));
			File socketFile = new File("/tmp/af-entityAuthentication");
			if (socketFile.exists())
				socketFile.delete();
			afUnixServerAddress = new AFUNIXSocketAddress(socketFile);
			//afUnixServer = new EntityAuthenticationServerNewRMI(core, afUnixServerAddress);
			
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

			kpGen.initialize(1024, new SecureRandom());
			keyPair = kpGen.generateKeyPair();
		} catch (InvalidKeyException e)
		{
			Logger.getLogger(EntityAuthenticationServerNewRMITest.class).error(new ErrorLogMessage("Caught exception"), e);
		} catch (UnrecoverableKeyException e)
		{
			Logger.getLogger(EntityAuthenticationServerNewRMITest.class).error(new ErrorLogMessage("Caught exception"), e);
		} catch (KeyStoreException e)
		{
			Logger.getLogger(EntityAuthenticationServerNewRMITest.class).error(new ErrorLogMessage("Caught exception"), e);
		} catch (NoSuchAlgorithmException e)
		{
			Logger.getLogger(EntityAuthenticationServerNewRMITest.class).error(new ErrorLogMessage("Caught exception"), e);
		} catch (NoSuchProviderException e)
		{
			Logger.getLogger(EntityAuthenticationServerNewRMITest.class).error(new ErrorLogMessage("Caught exception"), e);
		} catch (SignatureException e)
		{
			Logger.getLogger(EntityAuthenticationServerNewRMITest.class).error(new ErrorLogMessage("Caught exception"), e);
		} catch (IllegalStateException e)
		{
			Logger.getLogger(EntityAuthenticationServerNewRMITest.class).error(new ErrorLogMessage("Caught exception"), e);
		} catch (CertificateException e)
		{
			Logger.getLogger(EntityAuthenticationServerNewRMITest.class).error(new ErrorLogMessage("Caught exception"), e);
		} catch (FileNotFoundException e)
		{
			Logger.getLogger(EntityAuthenticationServerNewRMITest.class).error(new ErrorLogMessage("Caught exception"), e);
		} catch (IOException e)
		{
			Logger.getLogger(EntityAuthenticationServerNewRMITest.class).error(new ErrorLogMessage("Caught exception"), e);
		}
	}
	
	public EntityAuthenticationServerNewRMITest() throws Exception
	{

	}
	
	public SocketAddress getTCPConnectAddress()
	{
		InetSocketAddress returnAddress = tcpServer.getListenAddresses(new AddressFilter()
		{
			
			@Override
			public boolean add(InetSocketAddress checkAddress)
			{
				return (!(checkAddress instanceof AFUNIXSocketAddress));
			}
		})[0];
		return returnAddress;
	}
	
	public SocketAddress getAFUnixConnectAddress()
	{
		return afUnixServerAddress;
	}
	
	public void testRegisterServer() throws UnknownHostException, IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException, CertificateException, NoSuchProviderException, KeyStoreException
	{
		EntityAuthenticationServerFirehoseClient client = new EntityAuthenticationServerFirehoseClient(getTCPConnectAddress());
		try
		{
			X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
			X500Principal              dnName = new X500Principal("CN=Indelible FS Client self-signed cert");

			certGen.setSerialNumber(id.toBigInteger());
			certGen.setIssuerDN(dnName);
			certGen.setNotBefore(new Date(System.currentTimeMillis() - 10 * 60 * 1000));	// Allow for some clock skew
			certGen.setNotAfter(new Date(System.currentTimeMillis() + 3600 * 1000));
			certGen.setSubjectDN(dnName);                       // note: same as issuer

			certGen.setPublicKey(keyPair.getPublic());
			certGen.setSignatureAlgorithm(EntityAuthenticationServer.kCertificateSignatureAlg);

			X509Certificate mySelfSignedCert = certGen.generate(keyPair.getPrivate());
			client.registerServer(mySelfSignedCert);
		}
		finally
		{
			client.close();
		}
        
	}
	
	public void testAuthenticateServer() throws UnknownHostException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, CertificateEncodingException, UnrecoverableKeyException, CertificateParsingException, IllegalStateException, KeyStoreException, AuthenticationFailureException, ServerNotRegisteredException
	{
		SocketAddress tcpConnectAddress = getTCPConnectAddress();
		doTestAuthenticateServer(tcpConnectAddress);
		//SocketAddress afUnixConnectAddress = getAFUnixConnectAddress();
		//doTestAuthenticateServer(afUnixConnectAddress);
	}

	private void doTestAuthenticateServer(SocketAddress tcpConnectAddress)
			throws IOException, NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException, SignatureException,
			CertificateEncodingException, UnrecoverableKeyException,
			KeyStoreException, RemoteException, CertificateParsingException, IllegalStateException, AuthenticationFailureException, ServerNotRegisteredException
	{
		EntityAuthenticationServerFirehoseClient client = new EntityAuthenticationServerFirehoseClient(tcpConnectAddress);
		try
		{
			X500Principal entityName = new X500Principal(EntityAuthenticationClient.kEntityIDCNPrefix+id.toString());
    		PKCS10CertificationRequest certReq = new PKCS10CertificationRequest(EntityAuthenticationServer.kCertificateSignatureAlg,
    				entityName,
    				keyPair.getPublic(),
    				null,
    				keyPair.getPrivate());
    		byte [] encodedCertReq = certReq.getEncoded();
			EntityAuthentication authentication = client.authenticateServer(id, encodedCertReq);
			assertNotNull(authentication);
		}
		finally
		{
			client.close();
		}
	}
	
	public void testGetEntityID() throws UnknownHostException, IOException
	{
		EntityAuthenticationServerFirehoseClient client = new EntityAuthenticationServerFirehoseClient(getTCPConnectAddress());
		try
		{
			EntityID authenticationServerID = client.getEntityID();
			assertNotNull(authenticationServerID);
		}
		finally
		{
			client.close();
		}
	}
}
