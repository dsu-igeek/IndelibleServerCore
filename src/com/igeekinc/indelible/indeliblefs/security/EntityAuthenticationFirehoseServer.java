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
import java.nio.channels.ServerSocketChannel;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;

import org.apache.log4j.Logger;
import org.newsclub.net.unix.AFUNIXServerSocketChannelImpl;
import org.newsclub.net.unix.AFUNIXSocketAddress;

import com.igeekinc.firehose.CommandMessage;
import com.igeekinc.firehose.CommandResult;
import com.igeekinc.firehose.CommandToProcess;
import com.igeekinc.firehose.FirehoseServer;
import com.igeekinc.indelible.indeliblefs.security.remote.msgpack.AuthenticateServerMessage;
import com.igeekinc.indelible.indeliblefs.security.remote.msgpack.AuthenticateServerReplyMessage;
import com.igeekinc.indelible.indeliblefs.security.remote.msgpack.GetEntityIDMessage;
import com.igeekinc.indelible.indeliblefs.security.remote.msgpack.GetEntityIDReplyMessage;
import com.igeekinc.indelible.indeliblefs.security.remote.msgpack.RegisterServerMessage;
import com.igeekinc.indelible.oid.EntityID;
import com.igeekinc.util.logging.ErrorLogMessage;

public class EntityAuthenticationFirehoseServer extends FirehoseServer
{
	private EntityAuthenticationServerCore core;
	
	public EntityAuthenticationFirehoseServer(EntityAuthenticationServerCore core, InetSocketAddress serverAddress) throws IOException
	{
		this.core = core;
		KeyManager [] keyManagers = core.getKeyManagers();

		try
		{
			sslContext = SSLContext.getInstance("TLS");
			sslContext.init(keyManagers, null, new SecureRandom());

			if (serverAddress instanceof AFUNIXSocketAddress)
			{
				serverSocketChannel = AFUNIXServerSocketChannelImpl.open((AFUNIXSocketAddress)serverAddress);
				serverSocket = serverSocketChannel.socket();
			}
			else
			{
				serverSocketChannel = ServerSocketChannel.open();
				serverSocket = serverSocketChannel.socket();
				serverSocket.bind(serverAddress);
			}
			createSelectLoop();
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
	protected void processCommand(CommandToProcess commandToProcess)
			throws Exception
	{
		int commandCode = commandToProcess.getCommandToProcess().getCommandCode();
		Object reply = null;
		switch(EntityAuthenticationServerFirehoseClient.EntityAuthenticationCommand.getCommandForNum(commandCode))
		{
		case kRegisterServerCommand:
		{
			RegisterServerMessage registerCommand = (RegisterServerMessage)commandToProcess.getCommandToProcess();
			core.registerServer(registerCommand.getX509Certificate());
			reply = null;
			break;
		}
		case kAuthenticateServerCommand:
		{
			AuthenticateServerMessage authenticateCommand = (AuthenticateServerMessage)commandToProcess.getCommandToProcess();
			EntityAuthentication authentication = core.authenticateServer(authenticateCommand.getEntityID(), authenticateCommand.getEncodedCertificate());
			reply = new AuthenticateServerReplyMessage(authentication);

			break;
		}
		case kGetEntityID:
		{
			EntityID entityID = core.getEntityID();
			reply = new GetEntityIDReplyMessage(entityID);
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

}
