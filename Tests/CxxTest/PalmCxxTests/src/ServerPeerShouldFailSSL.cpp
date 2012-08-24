/*
 * ServerPeerShouldFailSSL.cpp
 *
 */


#define VERBOSE


#include "ServerPeerShouldFailSSL.h"
#include "CommonUtils.h"
#include "cxxtest/TestSuite.h"
#include "GMain.h"


ServerPeerShouldFailSSL::ServerPeerShouldFailSSL(PeerBaseParams & params)
:ServerPeerFullDuplexSSL(params, "ServerPeerShouldFailSSL ")
{
}


/*virtual*/
ServerPeerShouldFailSSL::~ServerPeerShouldFailSSL()
{
}


/*virtual*/
void ServerPeerShouldFailSSL::OnConnect(PmSockIOChannel *pChannel, PslError errorCode) {
	UTIL_ASSERT_THROW_FATAL(errorCode==PSL_ERR_SSL_PROTOCOL, MyName(),
			Err("PmSockAcceptCrypto: Expected PSL_ERR_SSL_PROTOCOL. Got ", errorCode).c_str() );

	PRINT_LINE("%s: PmSockAcceptCrypto: Expected PSL_ERR_SSL_PROTOCOL. Got PSL_ERR_SSL_PROTOCOL", MyName());

	g_main_loop_quit(gMain_.GetLoop());
}
