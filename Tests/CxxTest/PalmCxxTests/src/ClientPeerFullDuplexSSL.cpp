/* 
 * ClientPeerFullDuplexSSL.cpp
 *
 */


#define VERBOSE


#include <iostream>
#include <assert.h>


#include "ClientPeerFullDuplexSSL.h"
#include "CommonUtils.h"
#include "ConfigFile.h"
#include "Callback.h"
#include "cxxtest/TestSuite.h"
#include "PeerBaseParams.h"


using namespace std;


ClientPeerFullDuplexSSL::ClientPeerFullDuplexSSL(PeerBaseParams& params,
		const std::string& myName/*="ClientPeerFullDuplexSSL "*/)
:PeerFullDuplex(params, myName)
,pSSLContext_(NULL)
{
	assert(params.pSSLMethod_); //pSSLMethod_ parameter presence mandatory for this class
	pSSLMethod_ = params.pSSLMethod_;

	//just for log to be more comprehensive (768 and 769 are values got from logging, do not rely on these, to identify connection method)
	if (768==pSSLMethod_->version) {
		this->AppendToMyName("SSLv3 ");
	} else if (769==pSSLMethod_->version) {
		this->AppendToMyName("TLSv1 ");
	}

	pCryptoConfArgs_ = params.apCryptoConfArgs_.release();
}


ClientPeerFullDuplexSSL::~ClientPeerFullDuplexSSL() {
	//it may happen, that pSSLContext is NULL if an exception is thrown from UtilMakeSSLContext()
	if (pSSLContext_) {
		PmSockSSLCtxUnref(pSSLContext_);
	}

	delete pCryptoConfArgs_;
}


/*virtual*/
void ClientPeerFullDuplexSSL::Run() {
	PRINT_LINE("              ........................................................................................");
	PRINT_LINE("%s: Run", MyName() );

    //5. Kick off connection establishment
    //b) SSL connection
	if (!pCryptoConfArgs_) {
		pCryptoConfArgs_ = UtilCreateEmptyPmSockCryptoConfArgs();
	}

	PRINT_LINE("%s: config_.privateKeyPath=%s", MyName(), config_.privateKeyPath_.c_str());
    pSSLContext_ = UtilMakeSSLContext( MyName(), &config_.privateKeyPath_, pSSLMethod_ );

    PmSockSetUserData(pPmSockIOChannel_, this);
    PslError pslError = PmSockConnectCrypto(pPmSockIOChannel_, pSSLContext_,
    		pCryptoConfArgs_, Callback<IConnectObserver>);
	UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockConnectCrypto failed: ", pslError).c_str() );
}



