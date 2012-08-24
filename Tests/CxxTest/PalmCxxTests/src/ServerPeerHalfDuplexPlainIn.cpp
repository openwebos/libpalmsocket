/*
 * ServerPeerHalfDuplexPlainIn.cpp
 *
 */


#define VERBOSE


#include <assert.h>
#include <iostream>
#include <string.h>


#include "ServerPeerHalfDuplexPlainIn.h"
#include "DataIn.h"
#include "Data.h"
#include "GMain.h"
#include <cxxtest/TestSuite.h>
#include "CommonUtils.h"
#include "Callback.h"


using namespace std;


ServerPeerHalfDuplexPlainIn::ServerPeerHalfDuplexPlainIn(PeerBaseParams& params)
:PeerBase(params, "ServerPeerHalfDuplexPlainIn ")
,pWatchIn_(NULL)
{
}


ServerPeerHalfDuplexPlainIn::~ServerPeerHalfDuplexPlainIn() {
	FN_PRINT_LINE("...");

	//detach from main loop in case it was not detached in callback, by returning false
	g_source_destroy((GSource *)pWatchIn_);	//according to glib doc. detaches from main loop, if any.
	g_source_unref((GSource *)pWatchIn_);   //release our reference count
}


/*virtual*/
void ServerPeerHalfDuplexPlainIn::OnConnect(PmSockIOChannel *pChannel, PslError errorCode) {
	UTIL_ASSERT_THROW_FATAL(!errorCode, MyName(), Err("PmSockConnectPlain failed: ", errorCode).c_str() );

    //10. create a palmsock channel watch for IN
	CreateWatchWithCallback(pChannel, G_IO_IN, &pWatchIn_, (GSourceFunc)StaticChannelWatchOn_G_IO_IN, this, MyName());
}


/*virtual*/
void ServerPeerHalfDuplexPlainIn::Run() {
	FN_PRINT_LINE("...");

    //9.  Complete connection-establishment with the client: a) For plaintext mode:
    PmSockSetUserData(pPmSockIOChannel_, this);
    PslError pslError = PmSockConnectPlain(pPmSockIOChannel_, Callback<IConnectObserver>);
   	UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockConnectPlain failed: ", pslError).c_str() );
}

