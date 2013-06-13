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
 * ClientPeerHalfDuplexSSLIn.h
 *
 */


#ifndef CLIENTPEERHALFDUPLEXSSLIN_H_
#define CLIENTPEERHALFDUPLEXSSLIN_H_


#include "ClientPeerFullDuplexSSL.h"


/**
 * ClientPeer - stands for: initiating connection as from client side
 * HalfDuplex stands for half duplex data transfer
 * SSL - stands for secure connection
 * In - stands for receiving data from the other peer
 */
class ClientPeerHalfDuplexSSLIn: public ClientPeerFullDuplexSSL {
public:
	ClientPeerHalfDuplexSSLIn(PeerBaseParams& params);
	virtual ~ClientPeerHalfDuplexSSLIn();

	/** IConnectCallback */
	virtual void OnConnect(PmSockIOChannel *pChannel, PslError errorCode);

};


#endif /* CLIENTPEERHALFDUPLEXSSLIN_H_ */
