/*
 * ClientPeer.cpp
 *
 */


#define VERBOSE


#include <assert.h>
#include <iostream>
#include <string.h>


#include "ClientPeerHalfDuplexPlainOut.h"
#include "Data.h"
#include "GMain.h"
#include "CommonUtils.h"
#include "ConfigFile.h"
#include "Callback.h"
#include "DataSender.h"
#include "cxxtest/TestSuite.h"
#include "PipeFd.h"


using namespace std;


ClientPeerHalfDuplexPlainOut::ClientPeerHalfDuplexPlainOut(const PeerBaseParams& params)
:PeerBase(params, "ClientPeerHalfDuplexPlainOut ")
,pWatchOut_(NULL)
{
	pDataSender_ = new DataSender(config_, myName_);
}


ClientPeerHalfDuplexPlainOut::~ClientPeerHalfDuplexPlainOut() {
	FN_PRINT_LINE("...");

	//detach from main loop in case it was not detached in callback, by returning false
	g_source_destroy((GSource *)pWatchOut_); //according to glib doc. detaches from main loop, if any.
	g_source_unref((GSource *)pWatchOut_); 	 //release our reference count

	//signal an EOF to the other party
	g_io_channel_close((GIOChannel *)pPmSockIOChannel_);

    delete pDataSender_;
}


/*virtual*/
gboolean ClientPeerHalfDuplexPlainOut::ChannelWatchOn_G_IO_OUT(GIOChannel *pChannel, GIOCondition condition) {
	pDataSender_->Send(pChannel);

	if (pDataSender_->IsFinished()) {
		PRINT_LINE("%s will quit gmainloop ... ", MyName());
		g_main_loop_quit(gMain_.GetLoop());
	}

	bool staySubscribed = !pDataSender_->IsFinished();
	//false will detach watch from main loop
	return staySubscribed;
}


/*virtual*/
void ClientPeerHalfDuplexPlainOut::OnConnect(PmSockIOChannel *pChannel, PslError errorCode) {
	FN_PRINT_LINE("ClientPeer::ControlChannelCompletionCallback: errorCode = %s",
			PmSockErrStringFromError(errorCode));

	//7. create a palmsock channel watch for out
	CreateWatchWithCallback(pChannel, G_IO_OUT, &pWatchOut_, (GSourceFunc)PeerBase::StaticChannelWatchOn_G_IO_OUT,
			this, MyName() );
}


/*virtual*/
void ClientPeerHalfDuplexPlainOut::Run() {
    //5. Kick off connection establishment
    //a) plaintext connection
    PmSockSetUserData(pPmSockIOChannel_, this);
    PslError pslError = PmSockConnectPlain(pPmSockIOChannel_, Callback<IConnectObserver>);

	UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockConnectPlain failed", pslError).c_str() );
}

