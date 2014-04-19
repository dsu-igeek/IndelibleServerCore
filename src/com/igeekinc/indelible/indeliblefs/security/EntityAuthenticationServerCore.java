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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import com.igeekinc.indelible.indeliblefs.IndelibleEntity;
import com.igeekinc.indelible.oid.EntityID;
import com.igeekinc.indelible.oid.ObjectID;
import com.igeekinc.indelible.oid.ObjectIDFactory;
import com.igeekinc.util.logging.ErrorLogMessage;

public class EntityAuthenticationServerCore extends IndelibleEntity implements EntityAuthenticationServer
{
    private PrivateKey signingKey;
    private KeyStore keyStore;
    private X509Certificate rootCertificate;
    
    private static final String kRootCertAlias = "IndelibleRootCert";
    private static final String kDefaultKeyStorePassword = "idb301$";
    private static final String kSigningKeyAlias = "IndelibleRootSigningKey";
    private static final String kKeyStoreFileName = "IndelibleKeyStore";
    
    public EntityAuthenticationServerCore(File securityRootDir) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, 
    FileNotFoundException, IOException, UnrecoverableKeyException
    {
        super(null);
        if (securityRootDir == null)
            throw new IllegalArgumentException("securityRootDir cannot be null");
        if (!securityRootDir.isDirectory())
            throw new IllegalArgumentException("Security root dir '"+securityRootDir.getAbsolutePath()+"' is not a directory");
        File keyStoreFile = new File(securityRootDir, kKeyStoreFileName);
        keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(keyStoreFile), kDefaultKeyStorePassword.toCharArray());
        signingKey = (PrivateKey) keyStore.getKey(kSigningKeyAlias, kDefaultKeyStorePassword.toCharArray());
        rootCertificate = (X509Certificate) keyStore.getCertificate(kRootCertAlias);
        Principal rootPrincipal = rootCertificate.getIssuerDN();
        String uidString = EntityAuthenticationClient.getUID(rootPrincipal);
        EntityID rootID = (EntityID)ObjectIDFactory.reconstituteFromString(uidString);
        setEntityID(rootID);
    }
    
    public static final int kRequestingServerIDBytesOffset = 0;
    public static final int kChallengeBufferSize = ObjectID.kTotalBytes;

    /* (non-Javadoc)
     * @see com.igeekinc.indelible.indeliblefs.security.SecurityServer#registerServer(java.security.cert.X509Certificate)
     */
    public void registerServer(X509Certificate selfSignedServerCert) 
    throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, KeyStoreException
    {
        selfSignedServerCert.checkValidity();
        selfSignedServerCert.verify(selfSignedServerCert.getPublicKey(), "BC");
        EntityID serverID = EntityAuthentication.getObjectIDFromCertificateSerialNumber(selfSignedServerCert);
        logger.error(new ErrorLogMessage("Server "+serverID+" requesting registration"));
        if (keyStore.containsAlias(serverID.toString()))
        {
            Certificate checkKey = keyStore.getCertificate(serverID.toString());
            if (!checkKey.getPublicKey().equals(selfSignedServerCert.getPublicKey()))
            {
                logger.error(new ErrorLogMessage("Attempting to register server "+serverID+" but public key does not match previously registered public key"));
                throw new InvalidKeyException("Registered public key does not match");
            }
            logger.error(new ErrorLogMessage("Server "+serverID+" was already registered"));
            return; // OK, we're good
        }
        keyStore.setCertificateEntry(serverID.toString(), selfSignedServerCert);
        logger.error(new ErrorLogMessage("Server "+serverID+" registered"));
    }


    
    /* (non-Javadoc)
     * @see com.igeekinc.indelible.indeliblefs.security.SecurityServer#authenticateServer(com.igeekinc.indelible.oid.ServerID, java.security.PublicKey)
     */
    public EntityAuthentication authenticateServer(EntityID serverID, byte [] encodedCertReq) 
    throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, UnrecoverableKeyException, KeyStoreException, IOException, CertificateParsingException
    {
        Date startDate = new Date(System.currentTimeMillis() - (60L * 60L * 1000L));              // time from which certificate is valid
        Date expiryDate = new Date(startDate.getTime() + (30L * 24L * 60L * 60L * 1000L));             // time after which certificate is not valid
        BigInteger serialNumber = serverID.toBigInteger();     // serial number for certificate

        EntityAuthentication returnAuthentication = null;
        
        Certificate registeredCertificate = keyStore.getCertificate(serverID.toString());
        if (registeredCertificate != null)
        {
            PublicKey checkKey = registeredCertificate.getPublicKey();
            PKCS10CertificationRequest certReq = new PKCS10CertificationRequest(encodedCertReq);
            if (checkKey != null)
            {
                byte[] encodedCheckKey = checkKey.getEncoded();
                byte[] encodedCertKey = certReq.getPublicKey().getEncoded();
                if (Arrays.equals(encodedCheckKey, encodedCertKey))
                {
                    X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
                    X500Principal              dnName = new X500Principal(EntityAuthenticationClient.kEntityIDCNPrefix+serverID.toString());

                    certGen.setSerialNumber(serialNumber);
                    certGen.setIssuerDN(rootCertificate.getSubjectX500Principal());
                    certGen.setNotBefore(startDate);
                    certGen.setNotAfter(expiryDate);
                    certGen.setSubjectDN(dnName);                       // note: same as issuer
                    certGen.setPublicKey(certReq.getPublicKey());
                    certGen.setSignatureAlgorithm(kCertificateSignatureAlg);

                    certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                            new AuthorityKeyIdentifierStructure(rootCertificate));
                    certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
                            new SubjectKeyIdentifierStructure(certReq.getPublicKey()));

                    X509Certificate cert = certGen.generate(signingKey, "BC");
                    returnAuthentication = new EntityAuthentication(cert);
                }
            }
        }
        return returnAuthentication;
    }
    
    public Certificate getServerCertificate() throws KeyStoreException
    {
        return keyStore.getCertificate(kRootCertAlias);
    }
    
    /**
     * Returns the key managers to be used with the SSL socket that connects to this
     * AuthenticationServer
     * @return
     */
    public KeyManager [] getKeyManagers()
    {
    	try
		{
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, kDefaultKeyStorePassword.toCharArray());
            return keyManagerFactory.getKeyManagers();
		} catch (NoSuchAlgorithmException e)
		{
			Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
		} catch (KeyStoreException e)
		{
			Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
		} catch (UnrecoverableKeyException e)
		{
			Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
		}
    	throw new InternalError("Could not initialize key managers");
    }
    public static void initRootSecurity(File securityRootDir, EntityID securityServerID) 
    throws KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, 
    NoSuchProviderException, SignatureException, IllegalStateException, 
    CertificateException, FileNotFoundException, IOException
    {
        if (securityRootDir == null)
            throw new IllegalArgumentException("securityRootDir cannot be null");
        if (!securityRootDir.isDirectory())
            throw new IllegalArgumentException("Security root dir '"+securityRootDir.getAbsolutePath()+"' is not a directory");
        File keyStoreFile = new File(securityRootDir, kKeyStoreFileName);
        if (keyStoreFile.exists())
            throw new IOException("Keystore file '"+keyStoreFile.getAbsolutePath()+"' already exists - refusing to overwrite");
        KeyStore initKeyStore = KeyStore.getInstance("JKS");
        initKeyStore.load(null);
        Date startDate = new Date();              // time from which certificate is valid
        Date expiryDate = new Date(startDate.getTime() + (10L * 365L * 24L * 60L * 60L * 1000L));             // time after which certificate is not valid
        BigInteger serialNumber = securityServerID.toBigInteger();     // serial number for certificate
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(1024, new SecureRandom());
        KeyPair keyPair = kpGen.generateKeyPair();


        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        X500Principal              dnName = new X500Principal("CN=Indelible FS Auto-generated Root, UID="+securityServerID.toString());

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(dnName);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setSubjectDN(dnName);                       // note: same as issuer
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm(kCertificateSignatureAlg);

        X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");

        initKeyStore.setCertificateEntry(kRootCertAlias, cert);
        initKeyStore.setKeyEntry(kSigningKeyAlias, keyPair.getPrivate(), kDefaultKeyStorePassword.toCharArray(), new Certificate [] {cert});

        FileOutputStream keyStoreOutputStream = new FileOutputStream(keyStoreFile);
		initKeyStore.store(keyStoreOutputStream, kDefaultKeyStorePassword.toCharArray());
		keyStoreOutputStream.close();
    }
    
    public byte [] entityAuthenticationServerChallenge(byte [] bytesToSign)
    {
        Signature signingSignature;
        try
        {
            signingSignature = Signature.getInstance(kChallengeSignatureAlg, "BC");
            signingSignature.initSign(signingKey);
            signingSignature.update(bytesToSign);
            byte [] signedBytes = signingSignature.sign();
            return signedBytes;
        } catch (NoSuchAlgorithmException e)
        {
            Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
        } catch (NoSuchProviderException e)
        {
            Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
        } catch (InvalidKeyException e)
        {
            Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
        } catch (SignatureException e)
        {
            Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
        }
        throw new InternalError("Could not generate signing signature");
    }
}
