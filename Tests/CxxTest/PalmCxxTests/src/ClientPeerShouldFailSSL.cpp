/*
 * ClientPeerShouldFailSSL.cpp
 *
 */


#define VERBOSE


#include <assert.h>


#include "ClientPeerShouldFailSSL.h"
#include "CommonUtils.h"
#include "ConfigFile.h"
#include "Callback.h"
#include "cxxtest/TestSuite.h"
#include "GMain.h"


ClientPeerShouldFailSSL::ClientPeerShouldFailSSL(PeerBaseParams& params)
:ClientPeerFullDuplexSSL(params, "ClientPeerShouldFailSSL ")
{
}


static bool VerifyCallback(bool preverifyOK,
		struct x509_store_ctx_st *x509_ctx,
		const PmSockPeerVerifyCbInfo *pInfo)
{
	TS_ASSERT(!preverifyOK);
	TS_ASSERT(pInfo->pslVerifyError==PSL_ERR_SSL_HOSTNAME_MISMATCH);

	if (pInfo->pslVerifyError==PSL_ERR_SSL_HOSTNAME_MISMATCH) {
		ClientPeerShouldFailSSL *pInstance = (ClientPeerShouldFailSSL *)pInfo->userData;
		PRINT_LINE("%s PmSockCryptoConfArgs.verifyCb(): Expected PSL_ERR_SSL_HOSTNAME_MISMATCH. "
				"Got PSL_ERR_SSL_HOSTNAME_MISMATCH", pInstance->MyName());
	}

	return false; //should not continue to connect, regardless of preverify
}


/*virtual*/
void ClientPeerShouldFailSSL::Run() {
	PRINT_LINE("              ........................................................................................");
	PRINT_LINE("%s: Run", MyName() );

    //5. Kick off connection establishment
    //b) SSL connection
	if (!pCryptoConfArgs_) {
		pCryptoConfArgs_ = UtilCreateEmptyPmSockCryptoConfArgs();
	}

	if (pCryptoConfArgs_->enabledOpts & kPmSockCryptoConfigEnabledOpt_verifyCb) {
		pCryptoConfArgs_->verifyCb = VerifyCallback;
	}

	//if checkHostname is enabled, verifyOpts MUST be enabled too, for checkHostname to have any effect
	assert(
			!(pCryptoConfArgs_->verifyOpts & kPmSockCertVerifyOpt_checkHostname) ||
			(pCryptoConfArgs_->enabledOpts & kPmSockCryptoConfigEnabledOpt_verifyOpts  //verifyOpts enabled
				&& pCryptoConfArgs_->verifyOpts & kPmSockCertVerifyOpt_checkHostname)  //checkHostname enabled
	);

    pSSLContext_ = UtilMakeSSLContext( MyName(), &config_.privateKeyPath_, pSSLMethod_ );

    PmSockSetUserData(pPmSockIOChannel_, this);
    PslError pslError = PmSockConnectCrypto(pPmSockIOChannel_, pSSLContext_,
    		pCryptoConfArgs_, Callback<IConnectObserver>);
	UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockConnectCrypto failed: ", pslError).c_str() );
}


/*virtual*/
void ClientPeerShouldFailSSL::OnConnect(PmSockIOChannel *pChannel, PslError errorCode) {
	UTIL_ASSERT_THROW_FATAL(errorCode==PSL_ERR_SSL_CERT_VERIFY, MyName(),
			Err("PmSockConnectCrypto: Expected PSL_ERR_SSL_CERT_VERIFY. Got ", errorCode).c_str() );

	PRINT_LINE("%s: PmSockConnectCrypto: Expected PSL_ERR_SSL_CERT_VERIFY. Got PSL_ERR_SSL_CERT_VERIFY ", MyName());

	g_main_loop_quit(gMain_.GetLoop());
}

