/*
 * ServerPeerHalfDuplexSSLIn.cpp
 *
 */


#include "ServerPeerHalfDuplexSSLIn.h"
#include "CommonUtils.h"
#include "cxxtest/TestSuite.h"
#include "DummyDataSender.h"


ServerPeerHalfDuplexSSLIn::ServerPeerHalfDuplexSSLIn(PeerBaseParams& params)
:ServerPeerFullDuplexSSL(params, "ServerPeerHalfDuplexSSLIn ")
{
	//replace data sender with a dummy one
	delete pDataSender_;
	pDataSender_ = new DummyDataSender(config_, myName_);
}


/*virtual*/
ServerPeerHalfDuplexSSLIn::~ServerPeerHalfDuplexSSLIn() {
}


/*virtual*/
void ServerPeerHalfDuplexSSLIn::OnConnect(PmSockIOChannel *pChannel, PslError errorCode) {
	UTIL_ASSERT_THROW_FATAL(!errorCode, MyName(), Err("PmSockAcceptCrypto failed: ", errorCode).c_str() );

    //10. create a palmsock channel watch for IN
	CreateWatchWithCallback(pChannel, G_IO_IN, &pWatchIn_, (GSourceFunc)PeerBase::StaticChannelWatchOn_G_IO_IN,
			this, MyName() );
}
