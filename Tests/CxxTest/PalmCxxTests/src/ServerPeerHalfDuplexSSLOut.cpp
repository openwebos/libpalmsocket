/*
 * ServerPeerHalfDuplexSSLOut.cpp
 *
 */


#include "ServerPeerHalfDuplexSSLOut.h"
#include "CommonUtils.h"
#include "cxxtest/TestSuite.h"
#include "DummyDataReceiver.h"



ServerPeerHalfDuplexSSLOut::ServerPeerHalfDuplexSSLOut(PeerBaseParams& params)
:ServerPeerFullDuplexSSL(params, "ServerPeerHalfDuplexSSLOut ")
{
	//replace data receiver with a dummy one
	delete pDataReceiver_;
	pDataReceiver_ = new DummyDataReceiver(config_, myName_);
}


ServerPeerHalfDuplexSSLOut::~ServerPeerHalfDuplexSSLOut()
{
}


/*virtual*/
void ServerPeerHalfDuplexSSLOut::OnConnect(PmSockIOChannel *pChannel, PslError errorCode) {
	UTIL_ASSERT_THROW_FATAL(!errorCode, MyName(), Err("PmSockAcceptCrypto failed: ", errorCode).c_str() );

	//10. create watch for OUT
	CreateWatchWithCallback(pChannel, G_IO_OUT, &pWatchOut_, (GSourceFunc)PeerBase::StaticChannelWatchOn_G_IO_OUT,
			this, MyName() );
}

