/*
 * ClientPeerLeafFallbackNeg.cpp
 *
 */


#define VERBOSE


#include "ClientPeerLeafFallbackNeg.h"
#include "CommonUtils.h"
#include "cxxtest/TestSuite.h"
#include "GMain.h"


ClientPeerLeafFallbackNeg::ClientPeerLeafFallbackNeg(PeerBaseParams& params)
:ClientPeerShouldFailSSL(params)
{
}


/*virtual*/
void ClientPeerLeafFallbackNeg::OnConnect(PmSockIOChannel *pChannel, PslError errorCode) {
	UTIL_ASSERT_THROW_FATAL(errorCode==PSL_ERR_SSL_CERT_VERIFY, MyName(),
			Err("PmSockConnectCrypto: Expected PSL_ERR_SSL_CERT_VERIFY. Got ", errorCode).c_str() );

	PRINT_LINE("%s: PmSockConnectCrypto: Expected PSL_ERR_SSL_CERT_VERIFY. Got PSL_ERR_SSL_CERT_VERIFY ", MyName());

	PmSockPeerCertVerifyErrorInfo errorInfo;
	PslError pslError = PmSockGetPeerCertVerifyError(pChannel, &errorInfo);
	TS_ASSERT(!pslError);

	if (!pslError) {
		TS_ASSERT(errorInfo.opensslx509_v_err==X509_V_ERR_CERT_HAS_EXPIRED);

		if (errorInfo.opensslx509_v_err==X509_V_ERR_CERT_HAS_EXPIRED) {
			PRINT_LINE("%s: Expected PmSockPeerCertVerifyErrorInfo.opensslx509_v_err==X509_V_ERR_CERT_HAS_EXPIRED. Got X509_V_ERR_CERT_HAS_EXPIRED ", MyName() );
		}
	}

	g_main_loop_quit(gMain_.GetLoop());
}
