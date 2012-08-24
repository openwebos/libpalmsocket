/*
 * ServerPeerDeferredSSL.cpp
 *
 */


#define VERBOSE


#include <assert.h>
#include <algorithm>


#include "ServerPeerDeferredSSL.h"
#include "CommonUtils.h"
#include "ConfigFile.h"
#include "DataSender.h"
#include "Data.h"
#include "DataOut.h"
#include "ServerTasks.h"
#include "ServerTaskSendAndShutdown.h"
#include "GMain.h"
#include "Callback.h"
#include "cxxtest/TestSuite.h"
#include "PeerBaseParams.h"


using namespace std;


const unsigned int ServerPeerDeferredSSL::NUM_BYTES_TO_SEND=10000;


ServerPeerDeferredSSL::ServerPeerDeferredSSL(PeerBaseParams& params)
:PeerBase(params, "ServerPeerDeferredSSL ")
,pSSLContext_(NULL)
,pWatchOut_(NULL)
{
	tasks_.push_back(new TaskSend(pPmSockIOChannel_, *params.pConfig_, myName_) );
	tasks_.push_back(new TaskSleep());
	tasks_.push_back(new ServerTaskSendAndShutdown(pPmSockIOChannel_, gMain_, myName_));

	taskIterator_=tasks_.begin();
}


ServerPeerDeferredSSL::~ServerPeerDeferredSSL() {
	//detach from main loop in case it was not detached in callback, by returning false
	g_source_destroy((GSource *)pWatchOut_); //according to glib doc. detaches from main loop, if any.
	g_source_unref((GSource *)pWatchOut_);   //release our reference count

	PmSockSSLCtxUnref(pSSLContext_);

	for(vector<Task *>::iterator it=tasks_.begin(); it!=tasks_.end(); it++) {
		delete *it;
	}
}


/*virtual*/
void ServerPeerDeferredSSL::Run() {
	PRINT_LINE("              ........................................................................................");
	PRINT_LINE("%s: Run", MyName() );

    //9.  Complete connection-establishment with the client:
    PmSockSetUserData(pPmSockIOChannel_, this);

    PmSockCryptoConfArgs sslConfigArgs;
    sslConfigArgs.enabledOpts=0;
    sslConfigArgs.lifecycleCb=0;
    sslConfigArgs.verifyCb=0;
    sslConfigArgs.verifyOpts=0;

    pSSLContext_ = UtilMakeServerSSLContext(MyName(), config_.privateKeyPath_);
    assert(pSSLContext_);

    PslError pslError = PmSockAcceptCrypto(pPmSockIOChannel_, pSSLContext_, &sslConfigArgs, Callback<IConnectObserver>);
	UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockAcceptCrypto failed: ", pslError).c_str() );
}


/*virtual*/
void ServerPeerDeferredSSL::OnConnect(PmSockIOChannel *pChannel, PslError errorCode) {
	UTIL_ASSERT_THROW_FATAL(!errorCode, MyName(), Err("PmSockConnectCrypto failed: ", errorCode).c_str() );

	//10. create watch for OUT
	CreateWatchWithCallback(pChannel, G_IO_OUT, &pWatchOut_, (GSourceFunc)PeerBase::StaticChannelWatchOn_G_IO_OUT,
			this, MyName() );
}


/*virtual*/
gboolean ServerPeerDeferredSSL::ChannelWatchOn_G_IO_OUT(GIOChannel *pChannel, GIOCondition condition) {
	//FN_PRINT_LINE("");
	assert(taskIterator_!=tasks_.end());

	if (taskIterator_!=tasks_.end()) {
		Task *pCurrentTask = *taskIterator_;
		pCurrentTask->Execute();

		if (pCurrentTask->IsFinished()) taskIterator_++;
	}

	bool staySubscribed = (taskIterator_ != tasks_.end());

	return staySubscribed;
	//false will detach watch from main loop
}


