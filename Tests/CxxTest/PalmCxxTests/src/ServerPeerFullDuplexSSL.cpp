/*
 * ServerPeerFullDuplexSSL.cpp
 *
 */


#define VERBOSE


#include <palmsocket.h>
#include <assert.h>


#include "ServerPeerFullDuplexSSL.h"
#include "CommonUtils.h"
#include "ConfigFile.h"
#include "Callback.h"
#include "cxxtest/TestSuite.h"
#include "PeerBaseParams.h"


ServerPeerFullDuplexSSL::ServerPeerFullDuplexSSL(PeerBaseParams& params, const std::string& myName/*="ServerPeerFullDuplexSSL "*/)
:PeerFullDuplex(params, myName)
,pSSLContext_(NULL)
{
	pCryptoConfArgs_ = params.apCryptoConfArgs_.release();
}


ServerPeerFullDuplexSSL::~ServerPeerFullDuplexSSL() {
	delete pCryptoConfArgs_;

	//it may happen, that pSSLContext is NULL if an exception is thrown from UtilMakeServerSSLContext()
	if (pSSLContext_) {
		PmSockSSLCtxUnref(pSSLContext_);
	}
}


/*virtual*/
void ServerPeerFullDuplexSSL::Run() {
	PRINT_LINE("              ........................................................................................");
	PRINT_LINE("%s: Run", MyName() );

    //9. Complete connection-establishment with the client:
    PmSockSetUserData(pPmSockIOChannel_, this);

	if (!pCryptoConfArgs_) {
		pCryptoConfArgs_ = UtilCreateEmptyPmSockCryptoConfArgs();
	}

    pSSLContext_ = UtilMakeServerSSLContext(MyName(), config_.privateKeyPath_);
    assert(pSSLContext_);

    PslError pslError =
    		PmSockAcceptCrypto(pPmSockIOChannel_, pSSLContext_, pCryptoConfArgs_, Callback<IConnectObserver>);
	UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockAcceptCrypto failed: ", pslError).c_str() );
}










