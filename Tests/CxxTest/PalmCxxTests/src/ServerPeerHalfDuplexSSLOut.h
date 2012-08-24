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
 * ServerPeerHalfDuplexSSLOut.h
 *
 */


#ifndef SERVERPEERHALFDUPLEXSSLOUT_H_
#define SERVERPEERHALFDUPLEXSSLOUT_H_


#include "ServerPeerFullDuplexSSL.h"
#include "CommonUtils.h"
#include "cxxtest/TestSuite.h"
#include "DummyDataReceiver.h"


/**
 * ServerPeer - stands for: initiating connection as from server side
 * HalfDuplex - stands for half duplex data transfer
 * SSL - stands for secure connection
 * Out - stands for sending data to the other peer
 */
class ServerPeerHalfDuplexSSLOut: public ServerPeerFullDuplexSSL {
public:
	ServerPeerHalfDuplexSSLOut(PeerBaseParams& params);
	virtual ~ServerPeerHalfDuplexSSLOut();

	/** IConnectCallback */
	virtual void OnConnect(PmSockIOChannel *pChannel, PslError errorCode);
};


#endif /* SERVERPEERHALFDUPLEXSSLOUT_H_ */
