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
 * ServerPeerFullDuplexSSL.h
 *
 */


#ifndef SERVERPEERFULLDUPLEXSSL_H_
#define SERVERPEERFULLDUPLEXSSL_H_


#include "PeerFullDuplex.h"


/**
 * Full duplex, SSL connection
 * - can be used to instantiate server peer in a basic SSL test
 */
class ServerPeerFullDuplexSSL: public PeerFullDuplex {
private:
	//owned:
	PmSockSSLContext *pSSLContext_;
	PmSockCryptoConfArgs *pCryptoConfArgs_;

public:
	/**
	 * @see PeerBase
	 */
	ServerPeerFullDuplexSSL(PeerBaseParams& params, const std::string& myName="ServerPeerFullDuplexSSL ");
	virtual ~ServerPeerFullDuplexSSL();

	virtual void Run();
};


#endif /* SERVERPEERFULLDUPLEXSSL_H_ */
