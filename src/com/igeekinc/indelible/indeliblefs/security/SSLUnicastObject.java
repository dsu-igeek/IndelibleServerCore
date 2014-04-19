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

import java.rmi.NoSuchObjectException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.RemoteServer;
import java.rmi.server.RemoteStub;
import java.rmi.server.ServerCloneException;

import sun.rmi.server.UnicastServerRef;

public class SSLUnicastObject extends RemoteServer 
{

    /**
     * @serial port number on which to export object 
     */
    private int port = 0;

    /**
     * @serial client-side socket factory (if any) 
     */
    private IndelibleEntityAuthenticationClientRMIClientSocketFactory csf = null;

    /** 
     * @serial server-side socket factory (if any) to use when
     * exporting object 
     */
    private IndelibleEntityAuthenticationClientRMIServerSocketFactory ssf = null;

    /* indicate compatibility with JDK 1.1.x version of class */
    private static final long serialVersionUID = 4974527148936298033L;

    /**
     * Creates and exports a new UnicastRemoteObject object using the
     * particular supplied port and socket factories.
     * @param port the port number on which the remote object receives calls
     * (if <code>port</code> is zero, an anonymous port is chosen)
     * @param csf the client-side socket factory for making calls to the
     * remote object
     * @param ssf the server-side socket factory for receiving remote calls
     * @throws RemoteException if failed to export object
     * @since 1.2
     */
    protected SSLUnicastObject(int port,
    		IndelibleEntityAuthenticationClientRMIClientSocketFactory csf,
    		IndelibleEntityAuthenticationClientRMIServerSocketFactory ssf)
    throws RemoteException
    {
        this.port = port;
        this.csf = csf;
        this.ssf = ssf;
        exportObject((Remote) this, port, csf, ssf);
    }

    /**
     * Re-export the remote object when it is deserialized.
     */
    private void readObject(java.io.ObjectInputStream in) 
    throws java.io.IOException, java.lang.ClassNotFoundException
    {
        in.defaultReadObject();
        reexport();
    }

    /**
     * Returns a clone of the remote object that is distinct from
     * the original.
     *
     * @exception CloneNotSupportedException if clone failed due to
     * a RemoteException.
     * @return the new remote object
     * @since JDK1.1
     */
    public Object clone() throws CloneNotSupportedException
    {
        try {
            SSLUnicastObject cloned = (SSLUnicastObject) super.clone();
            cloned.reexport();
            return cloned;
        } catch (RemoteException e) {
            throw new ServerCloneException("Clone failed", e);
        }
    }

    /*
     * Exports this UnicastRemoteObject using its initialized fields because
     * its creation bypassed running its constructors (via deserialization
     * or cloning, for example).
     */
    private void reexport() throws RemoteException
    {
        if (csf == null && ssf == null) {
            exportObject((Remote) this, port);
        } else {
            exportObject((Remote) this, port, csf, ssf);
        }
    }

    /** 
     * Exports the remote object to make it available to receive incoming
     * calls using an anonymous port.
     * @param obj the remote object to be exported
     * @return remote object stub
     * @exception RemoteException if export fails
     * @since JDK1.1
     */
    public static RemoteStub exportObject(Remote obj)
    throws RemoteException
    {
        /*
         * Use UnicastServerRef constructor passing the boolean value true
         * to indicate that only a generated stub class should be used.  A
         * generated stub class must be used instead of a dynamic proxy
         * because the return value of this method is RemoteStub which a
         * dynamic proxy class cannot extend.
         */
        return (RemoteStub) exportObject(obj, new UnicastServerRef(true));
    }

    /** 
     * Exports the remote object to make it available to receive incoming
     * calls, using the particular supplied port.
     * @param obj the remote object to be exported
     * @param port the port to export the object on
     * @return remote object stub
     * @exception RemoteException if export fails
     * @since 1.2
     */
    public static Remote exportObject(Remote obj, int port)
    throws RemoteException
    {
        return exportObject(obj, new UnicastServerRef(port));
    }

    /**
     * Exports the remote object to make it available to receive incoming
     * calls, using a transport specified by the given socket factory.
     * @param obj the remote object to be exported
     * @param port the port to export the object on
     * @param csf the client-side socket factory for making calls to the
     * remote object
     * @param ssf the server-side socket factory for receiving remote calls
     * @return remote object stub
     * @exception RemoteException if export fails
     * @since 1.2
     */
    public static Remote exportObject(Remote obj, int port,
            RMIClientSocketFactory csf,
            RMIServerSocketFactory ssf)
    throws RemoteException
    {

        return exportObject(obj, new SSLUnicastServerRef2(port, csf, ssf));
    }

    /**
     * Removes the remote object, obj, from the RMI runtime. If
     * successful, the object can no longer accept incoming RMI calls.
     * If the force parameter is true, the object is forcibly unexported
     * even if there are pending calls to the remote object or the
     * remote object still has calls in progress.  If the force
     * parameter is false, the object is only unexported if there are
     * no pending or in progress calls to the object.
     *
     * @param obj the remote object to be unexported
     * @param force if true, unexports the object even if there are
     * pending or in-progress calls; if false, only unexports the object
     * if there are no pending or in-progress calls
     * @return true if operation is successful, false otherwise
     * @exception NoSuchObjectException if the remote object is not
     * currently exported
     * @since 1.2
     */
    public static boolean unexportObject(Remote obj, boolean force)
    throws java.rmi.NoSuchObjectException
    {
        return sun.rmi.transport.ObjectTable.unexportObject(obj, force);
    }

    /**
     * Exports the specified object using the specified server ref.
     */
    private static Remote exportObject(Remote obj, UnicastServerRef sref)
    throws RemoteException
    {
        // if obj extends UnicastRemoteObject, set its ref.
        if (obj instanceof SSLUnicastObject) {
            ((SSLUnicastObject) obj).ref = sref;
        }
        return sref.exportObject(obj, null, false);
    }

	public IndelibleEntityAuthenticationClientRMIClientSocketFactory getClientSocketFactory()
	{
		return csf;
	}

	public IndelibleEntityAuthenticationClientRMIServerSocketFactory getServerSocketFactory()
	{
		return ssf;
	}
}
