/* @@@LICENSE
*
*      Copyright (c) 2009-2011 Hewlett-Packard Development Company, L.P.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

/*
 * ServerSetUp.h
 *
 */

#ifndef SERVERSETUP_H_
#define SERVERSETUP_H_


#include <palmsocket.h>


#include "SetupBase.h"
#include "IObserver.h"


/**
 * Class for setting up resources necessary for a server to wait for client connections
 */
class ServerSetUp : public SetupBase, IThreadShutdownObserver {
private:
	int listenSocket_; /* FileDescriptor of socket which listens for incoming connections on server side */

	//owned:
	GIOChannel *pThreadShutdownNotifierChannel_; /** thread shutdown event will come on this channel */
	GSource *pThreadShutdownWatch_; /** watches G_IO_IN on pThreadShutdownNotifierChannel_ */

	PmSockIOChannel *pChannel_; /** palmsock channel created on socket returned by accept(listenSocket_)  ) */
	PeerBase *pServerPeer_;		/** peer instance on server side, will perform communication with the other party */

public:
	/** @see SetupBase */
	ServerSetUp(CreatePeerFunctionType Create, const Config& config, const PipeFd& pipeFd);
	virtual ~ServerSetUp();

	/**
	 * Starts ThreadFunction() in a new thread
	 * @returns the new thread
	 */
	GThread * Start();
	gpointer ThreadFunction();

	/** Callback function for watch on listensocket */
	gboolean ListenChannelWatchOn_G_IO_IN();

	/** IThreadShutdownObserver */
	virtual gboolean OnThreadShutdown(GIOChannel *pChannel, GIOCondition condition);
};


#endif /* SERVERSETUP_H_ */
