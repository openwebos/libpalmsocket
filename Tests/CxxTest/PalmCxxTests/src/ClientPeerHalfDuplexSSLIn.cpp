/*
 * ClientPeerHalfDuplexSSLIn.cpp
 *
 */


#include "ClientPeerHalfDuplexSSLIn.h"
#include "DummyDataSender.h"
#include "CommonUtils.h"
#include "cxxtest/TestSuite.h"


ClientPeerHalfDuplexSSLIn::ClientPeerHalfDuplexSSLIn(PeerBaseParams& params)
:ClientPeerFullDuplexSSL(params)
{
	//replace data sender with a dummy one
	delete pDataSender_;
	pDataSender_ = new DummyDataSender(config_, myName_);
}


/*virtual*/
ClientPeerHalfDuplexSSLIn::~ClientPeerHalfDuplexSSLIn() {
}


void ClientPeerHalfDuplexSSLIn::OnConnect(PmSockIOChannel *pChannel, PslError errorCode) {
	UTIL_ASSERT_THROW_FATAL(!errorCode, MyName(), Err("PmSockConnectCrypto failed: ", errorCode).c_str() );

    //10. create a palmsock channel watch for IN
	CreateWatchWithCallback(pChannel, G_IO_IN, &pWatchIn_, (GSourceFunc)PeerBase::StaticChannelWatchOn_G_IO_IN,
			this, MyName() );
}




