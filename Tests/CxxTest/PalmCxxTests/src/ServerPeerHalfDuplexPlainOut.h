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
 * ServerPeerOut.h
 *
 */

#ifndef SERVERPEEROUT_H_
#define SERVERPEEROUT_H_


#include "PeerBase.h"


class DataSender;


/*
 * Half duplex, Plaintext connection
 * - waits for Plaintext connections on server side
 * - sends data to a client peer
 */
class ServerPeerHalfDuplexPlainOut: public PeerBase {
private:
	//owned:
	PmSockWatch *pWatchOut_; //watch on G_IO_OUT for pPmSockIOChannel_
	DataSender *pDataSender_;

public:
	ServerPeerHalfDuplexPlainOut(PeerBaseParams& params);
	virtual ~ServerPeerHalfDuplexPlainOut();

	virtual void Run();

	virtual gboolean ChannelWatchOn_G_IO_OUT(GIOChannel *pChannel, GIOCondition condition);

	/** IConnectObserver */
	virtual void OnConnect(PmSockIOChannel *pChannel, PslError errorCode);
};


#endif /* SERVERPEEROUT_H_ */
