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
 * ClientPeerFullDuplexSSL.h
 *
 */


#ifndef CLIENTPEERFULLDUPLEXSSL_H_
#define CLIENTPEERFULLDUPLEXSSL_H_


#include <openssl/ssl.h>


#include "PeerFullDuplex.h"


/**
 * Full duplex, SSL connection
 * - can be used to instantiate client peer in a basic SSL test
 * - possibility to specify connection method in constructor
 */
class ClientPeerFullDuplexSSL : public PeerFullDuplex {
protected:
	//not owned:
	SSL_METHOD *pSSLMethod_;

	//owned:
	PmSockSSLContext *pSSLContext_;
	PmSockCryptoConfArgs *pCryptoConfArgs_;

public:
	/**
	 * @param params not const, see constructor for details
	 */
	ClientPeerFullDuplexSSL(PeerBaseParams& params, const std::string& myName="ClientPeerFullDuplexSSL ");
	virtual ~ClientPeerFullDuplexSSL();

	virtual void Run();
};


#endif /* CLIENTPEERFULLDUPLEXSSL_H_ */
