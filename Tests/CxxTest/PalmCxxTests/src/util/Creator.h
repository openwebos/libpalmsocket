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
 * Creator.h
 *
 */

#ifndef CREATOR_H_
#define CREATOR_H_


#include <openssl/ssl.h>
#include <iostream>


#include "CommonUtils.h"
#include "PeerBaseParams.h"
#include <string.h>


class PeerBaseParams;


/** Factory function. Will create PeerBase derived peer of type T */
template<class T>
PeerBase* CreatePeer(PeerBaseParams& params) {
	T* peer = new T(params);
	return peer;
}


/** Creates PeerBase derived peer with SSLv3 as SSL method type */
template<class T>
PeerBase *CreatePeer_SSLv3(PeerBaseParams& params) {
	params.pSSLMethod_ = SSLv3_method();

	T *pPeer = new T(params);
	return pPeer;
}


/** Creates PeerBase derived peer with TLSv1 as SSL method type */
template<class T>
PeerBase *CreatePeer_TLSv1(PeerBaseParams& params) {
	params.pSSLMethod_ = TLSv1_method();

	T *pPeer = new T(params);
	return pPeer;
}


/** Creates PeerBase derived peer with 'checkHostname' enabled, SSLv3 as SSL method type */
template<class T>
PeerBase *CreatePeer_CheckHostname(PeerBaseParams& params) {
	//crypto conf args
	PmSockCryptoConfArgs *pCryptoConfArgs=new PmSockCryptoConfArgs();
	pCryptoConfArgs->enabledOpts =
		  kPmSockCryptoConfigEnabledOpt_verifyOpts
		| kPmSockCryptoConfigEnabledOpt_verifyCb;

	pCryptoConfArgs->lifecycleCb=0;
	pCryptoConfArgs->verifyCb=0;

    /**
     * Perform hostname/ipaddress match against the
     * dNSName/ipAddress/CN fields of the peer certificate per
     * RFC-2595, RFC-2818, and accepted practices
     */
	pCryptoConfArgs->verifyOpts = kPmSockCertVerifyOpt_checkHostname;

	params.apCryptoConfArgs_.reset(pCryptoConfArgs);

	//ssl method
	params.pSSLMethod_ = SSLv3_method();

	//create the peer with given parameters
	T *pPeer = new T(params);
	return pPeer;
}


/** Creates PeerBase derived peer with 'fallbackToInstalledLeaf' enabled', SSLv3 as SSL method type */
template<class T>
PeerBase *CreatePeer_FallbackToInstalledLeaf(PeerBaseParams& params) {
	//crypto conf args
	PmSockCryptoConfArgs *pCryptoConfArgs=new PmSockCryptoConfArgs();

	pCryptoConfArgs->enabledOpts =
		  kPmSockCryptoConfigEnabledOpt_verifyOpts
		| kPmSockCryptoConfigEnabledOpt_verifyCb;

	pCryptoConfArgs->lifecycleCb=0;
	pCryptoConfArgs->verifyCb=0;
	pCryptoConfArgs->verifyOpts = kPmSockCertVerifyOpt_fallbackToInstalledLeaf;

	params.apCryptoConfArgs_.reset(pCryptoConfArgs);

	//ssl method
	params.pSSLMethod_ = SSLv3_method();

	//create the peer with given parameters
	T *pPeer = new T(params);
	return pPeer;
}


#endif /* CREATOR_H_ */
