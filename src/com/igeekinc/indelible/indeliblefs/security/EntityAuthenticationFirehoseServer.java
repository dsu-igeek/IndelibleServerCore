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
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;

import org.apache.log4j.Logger;

import com.igeekinc.firehose.CommandMessage;
import com.igeekinc.firehose.CommandResult;
import com.igeekinc.firehose.CommandToProcess;
import com.igeekinc.firehose.FirehoseChannel;
import com.igeekinc.firehose.FirehoseServer;
import com.igeekinc.firehose.FirehoseTarget;
import com.igeekinc.firehose.SSLSetup;
import com.igeekinc.indelible.indeliblefs.security.remote.msgpack.AuthenticateServerMessage;
import com.igeekinc.indelible.indeliblefs.security.remote.msgpack.AuthenticateServerReplyMessage;
import com.igeekinc.indelible.indeliblefs.security.remote.msgpack.GetEntityIDMessage;
import com.igeekinc.indelible.indeliblefs.security.remote.msgpack.GetEntityIDReplyMessage;
import com.igeekinc.indelible.indeliblefs.security.remote.msgpack.GetServerCertificateMessage;
import com.igeekinc.indelible.indeliblefs.security.remote.msgpack.GetServerCertificateReplyMessage;
import com.igeekinc.indelible.indeliblefs.security.remote.msgpack.RegisterServerMessage;
import com.igeekinc.indelible.oid.EntityID;
import com.igeekinc.util.logging.ErrorLogMessage;

public class EntityAuthenticationFirehoseServer extends FirehoseServer<Object> implements SSLSetup
{
	private EntityAuthenticationServerCore core;
	private SSLContext sslContext;
	FirehoseTarget target;
	public EntityAuthenticationFirehoseServer(EntityAuthenticationServerCore core, InetSocketAddress serverAddress) throws IOException
	{
		super();
		this.core = core;
		core.setServerAddress(serverAddress);
		KeyManager [] keyManagers = core.getKeyManagers();

		try
		{
			sslContext = SSLContext.getInstance("TLS");
			sslContext.init(keyManagers, null, new SecureRandom());

			target = new FirehoseTarget(serverAddress, this, null /* Not allowed to make reverse connections */, this);

		} catch (KeyManagementException e)
		{
			Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
			throw new IOException("Could not set up key managers");
		} catch (NoSuchAlgorithmException e)
		{
			Logger.getLogger(getClass()).error(new ErrorLogMessage("Caught exception"), e);
			throw new IOException("Could not set up key managers");
		}
	}
	
	@Override
	public Thread createSelectLoopThread(Runnable selectLoopRunnable)
	{
		return new Thread(selectLoopRunnable, "EntityAuthenticationServer select");
	}

	@Override
	protected void processCommand(Object clientInfo, CommandToProcess commandToProcess)
			throws Exception
	{
		int commandCode = commandToProcess.getCommandToProcess().getCommandCode();
		Object reply = null;
		switch(EntityAuthenticationServerFirehoseClient.EntityAuthenticationCommand.getCommandForNum(commandCode))
		{
		case kRegisterServerCommand:
		{
			logger.warn("Got register server command");
			RegisterServerMessage registerCommand = (RegisterServerMessage)commandToProcess.getCommandToProcess();
			core.registerServer(registerCommand.getX509Certificate());
			reply = null;
			break;
		}
		case kAuthenticateServerCommand:
		{
			logger.warn("Got authenticate server command");
			AuthenticateServerMessage authenticateCommand = (AuthenticateServerMessage)commandToProcess.getCommandToProcess();
			EntityAuthentication authentication = core.authenticateServer(authenticateCommand.getEntityID(), authenticateCommand.getEncodedCertReq());
			reply = new AuthenticateServerReplyMessage(authentication);

			break;
		}
		case kGetEntityID:
		{
			logger.warn("Got get entity id command");
			EntityID entityID = core.getEntityID();
			reply = new GetEntityIDReplyMessage(entityID);
			break;
		}
		case kGetServerCertificate:
		{
			logger.warn("Got get server certificate command");
			reply = new GetServerCertificateReplyMessage((X509Certificate) core.getServerCertificate());
			break;
		}
		}
		CommandResult result = new CommandResult(0, reply);
		commandCompleted(commandToProcess, result);
	}

	@Override
	protected Class<? extends CommandMessage> getClassForCommandCode(
			int payloadType)
	{
		switch(EntityAuthenticationServerFirehoseClient.EntityAuthenticationCommand.getCommandForNum(payloadType))
		{
		case kRegisterServerCommand:
			return RegisterServerMessage.class;
		case kAuthenticateServerCommand:
			return AuthenticateServerMessage.class;
		case kGetEntityID:
			return GetEntityIDMessage.class;
		case kGetServerCertificate:
			return GetServerCertificateMessage.class;
		default:
			break;
		}
		return null;
	}

	@Override
	protected Class<? extends Object> getReturnClassForCommandCode(
			int payloadType)
	{
		return null;
	}

	@Override
	public boolean useSSL()
	{
		return true;
	}

	@Override
	public SSLContext getSSLContextForSocket(SocketChannel newChannel)
			throws IOException
	{
		return sslContext;
	}

	@Override
	protected Object createClientInfo(FirehoseChannel channel)
	{
		return null;
	}

	@Override
	public boolean removeTarget(FirehoseTarget removeTarget) 
	{
		logger.error(new ErrorLogMessage("Removing target "+removeTarget));
		try
		{
			boolean removed = super.removeTarget(removeTarget);
			return removed;
		}
		finally
		{
			synchronized(targets)
			{
				if (targets.size() == 0)
				{
					logger.error(new ErrorLogMessage("All EntityAuthenticationServer targets have been removed - exiting!"));
					System.exit(1);
				}
			}
		}
	}

	@Override
	public int getExtendedErrorCodeForThrowable(Throwable t)
	{
		return EntityAuthenticationServerFirehoseClient.getExtendedErrorCodeForThrowableStatic(t);
	}

	@Override
	public Throwable getExtendedThrowableForErrorCode(int errorCode)
	{
		return EntityAuthenticationServerFirehoseClient.getExtendedThrowableForErrorCodeStatic(errorCode);
	}
}
