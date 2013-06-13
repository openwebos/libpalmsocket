/* @@@LICENSE
*
*      Copyright (c) 2009-2013 LG Electronics, Inc.
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
 * ServerPeerDeferredSSL.h
 *
 */


#ifndef SERVERPEERDEFERREDSSL_H_
#define SERVERPEERDEFERREDSSL_H_


#include <vector>


#include "PeerBase.h"


class Task;


/**
 * Deferred test server peer
 * Executes 3 tasks on G_IO_OUT events:
 * 1. send 10000 bytes
 * 2. sleeps for 5 seconds
 * 3. sends 1 final byte, than initiates bidirectional shutdown
 */
class ServerPeerDeferredSSL: public PeerBase {
private:
	std::vector<Task *>::iterator taskIterator_; /** pointing to the next executable task */

	//owned:
	std::vector<Task *> tasks_;
	PmSockSSLContext *pSSLContext_;
	PmSockWatch *pWatchOut_;  /** watch on pPmSockIOChannel_ for G_IO_OUT */

public:
	/** number of bytes sent from server peer to client in deferred test */
	static const unsigned int NUM_BYTES_TO_SEND;

public:
	/**
	 * @see PeerBase
	 */
	ServerPeerDeferredSSL(PeerBaseParams& params);
	virtual ~ServerPeerDeferredSSL();

	virtual void Run();

	/** IConnectObserver */
	virtual void OnConnect(PmSockIOChannel *pChannel, PslError errorCode);
	virtual gboolean ChannelWatchOn_G_IO_OUT(GIOChannel *pChannel, GIOCondition condition);
};


#endif /* SERVERPEERDEFERREDSSL_H_ */
