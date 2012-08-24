/*
 * ClientPeerDeferredSSL.cpp
 *
 */


#define VERBOSE


#include <assert.h>


#include "ClientPeerDeferredSSL.h"
#include "CommonUtils.h"
#include "ConfigFile.h"
#include "DataReceiver.h"
#include "ServerPeerDeferredSSL.h"
#include "DataIn.h"
#include <cxxtest/TestSuite.h>
#include "Data.h"
#include "ClientTasks.h"
#include "GMain.h"
#include "Callback.h"
#include "PeerBaseParams.h"


using namespace std;


ClientPeerDeferredSSL::ClientPeerDeferredSSL(PeerBaseParams& params)
:PeerBase(params, "ClientPeerDeferredSSL ")
,pSSLContext_(NULL)
,pWatchIn_(NULL)
{
	tasks_.push_back(new TaskReceive(pPmSockIOChannel_, *params.pConfig_, myName_) );
	tasks_.push_back(new TaskShutdown(pPmSockIOChannel_, gMain_, myName_));

	taskIterator_=tasks_.begin();
}


ClientPeerDeferredSSL::~ClientPeerDeferredSSL() {
	//detach from main loop in case it was not detached in callback, by returning false
	g_source_destroy((GSource *)pWatchIn_); //according to glib doc. detaches from main loop, if any.
	g_source_unref((GSource *)pWatchIn_);   //release our reference count

	//it may happen pSSLContext_ was not initialized, in case UtilMakeSSLContext threw an exception
	if (pSSLContext_) {
		PmSockSSLCtxUnref(pSSLContext_);
	}

	for(vector<Task *>::iterator it=tasks_.begin(); it!=tasks_.end(); it++) {
		delete *it;
	}
}


/*virtual*/
void ClientPeerDeferredSSL::Run() {
	PRINT_LINE("              ........................................................................................");
	PRINT_LINE("%s: Run", MyName() );

    //5. Kick off connection establishment
    //b) SSL connection
    PmSockCryptoConfArgs sslConfigArgs;
    sslConfigArgs.enabledOpts=0;
    sslConfigArgs.lifecycleCb=0;
    sslConfigArgs.verifyCb=0;
    sslConfigArgs.verifyOpts=0;

    assert(NULL==pSSLContext_);
    pSSLContext_ = UtilMakeSSLContext( MyName(), &config_.privateKeyPath_, /*pSSLMethod_*/0);

    PmSockSetUserData(pPmSockIOChannel_, this);
    PslError pslError = PmSockConnectCrypto(pPmSockIOChannel_, pSSLContext_, &sslConfigArgs, Callback<IConnectObserver>);
	UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockConnectCrypto failed: ", pslError).c_str() );
}


/*virtual*/
void ClientPeerDeferredSSL::OnConnect(PmSockIOChannel *pChannel, PslError errorCode) {
	FN_PRINT_LINE(" ");
	UTIL_ASSERT_THROW_FATAL(!errorCode, MyName(), Err("PmSockConnectCrypto failed: ", errorCode).c_str() );

    //10. create a palmsock channel watch for IN
	CreateWatchWithCallback(pChannel, G_IO_IN, &pWatchIn_, (GSourceFunc)PeerBase::StaticChannelWatchOn_G_IO_IN,
			this, MyName() );
}


/*virtual*/
gboolean ClientPeerDeferredSSL::ChannelWatchOn_G_IO_IN(GIOChannel *pChannel, GIOCondition condition) {
	assert(taskIterator_!=tasks_.end());

	if (taskIterator_!=tasks_.end()) {
		Task *pCurrentTask = *taskIterator_;
		pCurrentTask->Execute();

		if (pCurrentTask->IsFinished()) taskIterator_++;
	}

	bool staySubscribed = (taskIterator_ != tasks_.end());
	return staySubscribed;
}



