/*
 * PeerFullDuplexPlainSingleWatch.cpp
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


#include "PeerFullDuplexPlainSingleWatch.h"
#include "GMain.h"
#include "CommonUtils.h"
#include "ConfigFile.h"
#include "Data.h"
#include "DataSender.h"
#include "DataIn.h"
#include "DataReceiver.h"
#include "Callback.h"
#include "cxxtest/TestSuite.h"


PeerFullDuplexPlainSingleWatch::PeerFullDuplexPlainSingleWatch(PeerBaseParams& params)
:PeerBase(params, "PeerFullDuplexPlainSingleWatch ")
,pWatch_(NULL)
{
	pDataSender_ = new DataSender(config_, myName_ );
}


PeerFullDuplexPlainSingleWatch::~PeerFullDuplexPlainSingleWatch() {
	PRINT_LINE("%s               destructor ...", MyName() );
	LOGVAR(pDataReceiver_->GetTotalBytesReceived() );

	delete pDataSender_;

	if (pWatch_) {
		g_source_destroy((GSource *)pWatch_);	///< detach from main loop
		g_source_unref((GSource *)pWatch_); ///< release our reference count
	}
}


static gboolean StaticChannelWatch(GIOChannel *pChannel, GIOCondition condition, gpointer data) {
	return ((PeerFullDuplexPlainSingleWatch *)data)->ChannelWatch(pChannel, condition);
}


/*virtual*/
void PeerFullDuplexPlainSingleWatch::OnConnect(PmSockIOChannel *pChannel, PslError errorCode) {
	UTIL_ASSERT_THROW_FATAL(!errorCode, MyName(), Err("PmSockConnectPlain failed: ", errorCode).c_str() );

    //10. create a palmsock channel watch for IN, OUT
	GIOCondition condition = (GIOCondition)(G_IO_IN | G_IO_OUT);
	CreateWatchWithCallback(pChannel, condition, &pWatch_, (GSourceFunc)StaticChannelWatch, this, MyName() );
}


void PeerFullDuplexPlainSingleWatch::Run() {
	PRINT_LINE("              ........................................................................................");
	FN_PRINT_LINE(" RUNNING");

    //9.  Complete connection-establishment with the client: a) For plaintext mode:
    PmSockSetUserData(pPmSockIOChannel_, this);
    PslError pslError = PmSockConnectPlain(pPmSockIOChannel_, Callback<IConnectObserver>);
    UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockConnectPlain failed:", pslError).c_str() );
}


/*virtual*/
gboolean PeerFullDuplexPlainSingleWatch::ChannelWatch(GIOChannel *pChannel, GIOCondition ioCondition) {
	if (ioCondition | G_IO_IN) {
		pDataReceiver_->Receive(pChannel);
	}

	if (ioCondition | G_IO_OUT) {
		pDataSender_->Send(pChannel);
	}

	if (pDataSender_->IsFinished() && pDataReceiver_->IsFinished() ) {
		PRINT_LINE("%s will quit gmainloop ... ", MyName());
		g_main_loop_quit(gMain_.GetLoop());
	}

	bool staySubscribed = !pDataReceiver_->IsFinished() || !pDataSender_->IsFinished();
	return staySubscribed;
	//false will detach watch from main loop
}

