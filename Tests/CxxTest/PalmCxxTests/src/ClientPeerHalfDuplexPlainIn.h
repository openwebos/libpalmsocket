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
 * ClientPeerIn.h
 *
 */

#ifndef CLIENTPEERIN_H_
#define CLIENTPEERIN_H_


#include "PeerBase.h"


/*
 * Half duplex, Plaintext connection
 * - connects to server using plaintext connection
 * - receives data from server peer
 */
class ClientPeerHalfDuplexPlainIn : public PeerBase {
private:
	//owned:
	PmSockWatch *pWatchIn_;  //watch on G_IO_IN for pChannel

public:
	ClientPeerHalfDuplexPlainIn(PeerBaseParams& params);
	virtual ~ClientPeerHalfDuplexPlainIn();

	virtual void Run();

	/** IConnectObserver */
	virtual void OnConnect(PmSockIOChannel *pChannel, PslError errorCode);
};


#endif /* CLIENTPEERIN_H_ */
