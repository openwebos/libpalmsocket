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
 * PeerBaseParams.h
 *
 */

#ifndef PEERBASEPARAMS_H_
#define PEERBASEPARAMS_H_


#include <palmsocket.h>
#include <openssl/ssl.h>
#include <auto_ptr.h>


class GMain;
class Config;
class DataReceiver;
class Channels;
class PipeFd;


/**
 * None of the members is owned
 */
class PeerBaseParams {
public:
	const GMain * const pGMain_; 		/** @see PeerBase */
	PmSockIOChannel * const pChannel_;  /** @see PeerBase */
	const Config * const pConfig_;		/** @see PeerBase */
	const PipeFd * const pPipeFd_;		/** @see PeerBase */

	//optional parameters
	/**
	 * Will contain a pointer returned by SSLv3_method() and similar functions.
	 * These functions always return a pointer to a static object, no need to dispose
	 */
	SSL_METHOD *pSSLMethod_;
	std::auto_ptr<PmSockCryptoConfArgs> apCryptoConfArgs_;

public:
	PeerBaseParams(GMain *pGMain, PmSockIOChannel *pChannel, const Config *pConfig, const PipeFd *pPipeFd);

private: //forbidden
	PeerBaseParams(const PeerBaseParams& );
	PeerBaseParams& operator=(const PeerBaseParams& );

};


#endif /* PEERBASEPARAMS_H_ */
