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
 * ServerPeerShouldFailSSL.h
 *
 */


#ifndef SERVERPEERSHOULDFAILSSL_H_
#define SERVERPEERSHOULDFAILSSL_H_


#include "ServerPeerFullDuplexSSL.h"


/**
 * ServerPeer - stands for: initiating connection as from server side
 * ShouldFail - stands for: used in tests where server is not supposed to successfully connect to client
 * SSL - stands for secure connection
 */
class ServerPeerShouldFailSSL: public ServerPeerFullDuplexSSL {
public:
	ServerPeerShouldFailSSL(PeerBaseParams& params);
	virtual ~ServerPeerShouldFailSSL();

	/** IConnectCallback */
	virtual void OnConnect(PmSockIOChannel *pChannel, PslError errorCode);
};


#endif /* SERVERPEERSHOULDFAILSSL_H_ */
