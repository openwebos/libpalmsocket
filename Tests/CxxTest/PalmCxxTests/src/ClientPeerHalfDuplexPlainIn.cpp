/*
 * ClientPeerIn.cpp
 *
 */


#define VERBOSE


#include <assert.h>
#include <iostream>
#include <string.h>
#include <glib.h>


#include "ClientPeerHalfDuplexPlainIn.h"
#include "GMain.h"
#include "DataIn.h"
#include "Data.h"
#include "CommonUtils.h"
#include "Callback.h"
#include "cxxtest/TestSuite.h"


using namespace std;


ClientPeerHalfDuplexPlainIn::ClientPeerHalfDuplexPlainIn(PeerBaseParams& params)
:PeerBase(params, "ClientPeerHalfDuplexPlainIn ")
,pWatchIn_(NULL)
{
}


ClientPeerHalfDuplexPlainIn::~ClientPeerHalfDuplexPlainIn() {
	FN_PRINT_LINE("...");

	//detach from main loop in case it was not detached in callback, by returning false
	g_source_destroy((GSource *)pWatchIn_);	//according to glib doc, detaches from main loop, if any
	g_source_unref((GSource *)pWatchIn_);   //release our reference count
}


/*virtual*/
void ClientPeerHalfDuplexPlainIn::OnConnect(PmSockIOChannel *pChannel, PslError errorCode) {
	UTIL_ASSERT_THROW_FATAL(!errorCode, MyName(), Err("PmSockConnectPlain failed: ", errorCode).c_str() );

	//7. create a palmsock channel watch
	CreateWatchWithCallback(pChannel, G_IO_IN, &pWatchIn_,
			(GSourceFunc)PeerBase::StaticChannelWatchOn_G_IO_IN, this, MyName() );
}


/*virtual*/
void ClientPeerHalfDuplexPlainIn::Run() {
    //5. Kick off connection establishment
    //a) plaintext connection
    PmSockSetUserData(pPmSockIOChannel_, this);
    PslError pslError = PmSockConnectPlain(pPmSockIOChannel_, Callback<IConnectObserver>);

	UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockConnectPlain failed: ", pslError).c_str() );
}

