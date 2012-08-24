/*
 * ServerPeerOut.cpp
 *
 */


#define VERBOSE


#include <assert.h>
#include <iosfwd>
#include "palmsockerror.h"
#include <palmsocket.h>
#include <string.h>
#include <iostream>
#include <glib/gmain.h>


#include "ServerPeerHalfDuplexPlainOut.h"
#include "GMain.h"
#include "CommonUtils.h"
#include "ConfigFile.h"
#include "Data.h"
#include "Callback.h"
#include "DataSender.h"
#include "cxxtest/TestSuite.h"


using namespace std;


ServerPeerHalfDuplexPlainOut::ServerPeerHalfDuplexPlainOut(PeerBaseParams& params)
:PeerBase(params, "ServerPeerHalfDuplexPlainOut ")
,pWatchOut_(NULL)
{
	pDataSender_ = new DataSender(config_, myName_);
}


ServerPeerHalfDuplexPlainOut::~ServerPeerHalfDuplexPlainOut() {
	FN_PRINT_LINE("...");

	//detach from main loop in case it was not detached in callback, by returning false
	g_source_destroy((GSource *)pWatchOut_); //according to glib doc. detaches from main loop, if any.
	g_source_unref((GSource *)pWatchOut_);   //release our reference count

	//signal an EOF to the other party
    g_io_channel_close((GIOChannel *)pPmSockIOChannel_);

    delete pDataSender_;
}


/*virtual*/
void ServerPeerHalfDuplexPlainOut::OnConnect(PmSockIOChannel * pChannel, PslError errorCode) {
    //10. create a palmsock channel watch for OUT
	CreateWatchWithCallback(pChannel, G_IO_OUT, &pWatchOut_,
			(GSourceFunc)PeerBase::StaticChannelWatchOn_G_IO_OUT, this, MyName());
}


/*virtual*/
void ServerPeerHalfDuplexPlainOut::Run() {
    //9.  Complete connection-establishment with the client: a) For plaintext mode:
    PmSockSetUserData(pPmSockIOChannel_, this);
    PslError pslError = PmSockConnectPlain(pPmSockIOChannel_, Callback<IConnectObserver>);
    UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockConnectPlain failed:", pslError).c_str() );
}


/*virtual*/
gboolean ServerPeerHalfDuplexPlainOut::ChannelWatchOn_G_IO_OUT(GIOChannel *pChannel, GIOCondition condition) {
	pDataSender_->Send(pChannel);

	if (pDataSender_->IsFinished()) {
		PRINT_LINE("%s will quit gmainloop ... ", MyName());
		g_main_loop_quit(gMain_.GetLoop());
	}

	bool staySubscribed = !pDataSender_->IsFinished();
	return staySubscribed;
	//false will detach watch from main loop
}


