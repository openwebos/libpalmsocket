/*
 * ServerPeerFullDuplexPlain.cpp
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


#include "PeerFullDuplexPlain.h"
#include "GMain.h"
#include "CommonUtils.h"
#include "ConfigFile.h"
#include "DataSender.h"
#include <cxxtest/TestSuite.h>
#include "DataReceiver.h"
#include "Callback.h"


PeerFullDuplexPlain::PeerFullDuplexPlain(const PeerBaseParams& params)
:PeerFullDuplex(params, "PeerFullDuplexPlain ")
{
}


PeerFullDuplexPlain::~PeerFullDuplexPlain() {
}


/*virtual*/
void PeerFullDuplexPlain::Run() {
	PRINT_LINE("              ........................................................................................");
	FN_PRINT_LINE(" RUNNING");

    //9.  Complete connection-establishment with the client: a) For plaintext mode:
    PmSockSetUserData(pPmSockIOChannel_, this);
    PslError pslError = PmSockConnectPlain(pPmSockIOChannel_, Callback<IConnectObserver>);
    UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockConnectPlain failed:", pslError).c_str() );
}


