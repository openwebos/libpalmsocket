/*
 * ClientPeerHalfDuplexSSLOut.cpp
 *
 */


#include "ClientPeerHalfDuplexSSLOut.h"
#include "CommonUtils.h"
#include "cxxtest/TestSuite.h"
#include "DummyDataReceiver.h"


ClientPeerHalfDuplexSSLOut::ClientPeerHalfDuplexSSLOut(PeerBaseParams& params)
:ClientPeerFullDuplexSSL(params, "ClientPeerHalfDuplexSSLOut ")
{
	//replace data receiver with a dummy one
	delete pDataReceiver_;
	pDataReceiver_ = new DummyDataReceiver(config_, myName_);
}


/*virtual*/
ClientPeerHalfDuplexSSLOut::~ClientPeerHalfDuplexSSLOut() {
}


/*virtual*/
void ClientPeerHalfDuplexSSLOut::OnConnect(PmSockIOChannel *pChannel, PslError errorCode) {
	UTIL_ASSERT_THROW_FATAL(!errorCode, MyName(), Err("PmSockConnectCrypto failed: ", errorCode).c_str() );

	//10. create watch for OUT
	CreateWatchWithCallback(pChannel, G_IO_OUT, &pWatchOut_, (GSourceFunc)PeerBase::StaticChannelWatchOn_G_IO_OUT,
			this, MyName() );
}

