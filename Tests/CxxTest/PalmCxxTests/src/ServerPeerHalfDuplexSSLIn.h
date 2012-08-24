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
 * ServerPeerHalfDuplexSSLIn.h
 *
 */

#ifndef SERVERPEERHALFDUPLEXSSLIN_H_
#define SERVERPEERHALFDUPLEXSSLIN_H_


#include "ServerPeerFullDuplexSSL.h"


/**
 * ServerPeer - stands for: initiating connection as from server side
 * HalfDuplex -  stands for half duplex data transfer
 * SSL - stands for secure connection
 * In - stands for receiving data from the other peer
 */
class ServerPeerHalfDuplexSSLIn : public ServerPeerFullDuplexSSL {
public:
	ServerPeerHalfDuplexSSLIn(PeerBaseParams& params);
	virtual ~ServerPeerHalfDuplexSSLIn();

	/** IConnectCallback */
	virtual void OnConnect(PmSockIOChannel *pChannel, PslError errorCode);
};


#endif /* SERVERPEERHALFDUPLEXSSLIN_H_ */
