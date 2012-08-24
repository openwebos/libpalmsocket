/*
 * ClientSetUp.cpp
 *
 */


#define VERBOSE


#include <iostream>
#include <palmsockerror.h>
#include <palmsocket.h>
#include <sys/socket.h>
#include <string.h>
#include <assert.h>


#include "ClientSetUp.h"
#include "ClientPeerHalfDuplexPlainOut.h"
#include "ThreadUtil.h"
#include "GMain.h"
#include "CommonUtils.h"
#include "ConfigFile.h"
#include "cxxtest/TestSuite.h"
#include "PipeFd.h"
#include "PeerBaseParams.h"


using namespace std;


ClientSetUp::ClientSetUp(CreatePeerFunctionType create, const Config& config, const PipeFd& pipeFd)
:SetupBase(create, config, pipeFd, "ClientSetUp ")
,pChannel_(NULL)
{
}


ClientSetUp::~ClientSetUp() {
	g_io_channel_unref((GIOChannel *)pChannel_);
}


GThread * ClientSetUp::Start() {
	GThread *pThread = g_thread_create(&StaticThreadFunction<ClientSetUp>, this, /*joinable*/true, /* **error */NULL);
	return pThread;
}


gpointer ClientSetUp::ThreadFunction() {
	//this is the deepest point (in stack) where we can catch the exceptions, deeper than this it's another thread already
	try {
		//2.  Create palmsock thread context
		PmSockThreadContext *pThreadContext = NULL;

		PslError pslError =
				PmSockThreadCtxNewFromGMain(pGMain_->GetContext(), /*userLabel*/NULL, &pThreadContext);
		UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockThreadCtxNewFromGMain failed: ", pslError).c_str());

		//3. Create palmsock channel
		assert(pChannel_==NULL);
		pslError = PmSockCreateChannel(pThreadContext, (PmSockOptionFlags)0, /*userLabel*/NULL, &pChannel_);

		/// Release our reference to thread ctx
		PmSockThreadCtxUnref(pThreadContext);

		UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockCreateChannel failed: ", pslError).c_str());

		//4. set the hostname or IP address
		const int listenPort = config_.serverListenPort_;

		PRINT_LINE("%s: config_.address_=%s", MyName(), config_.address_.c_str());
		const char * serverAddress = config_.address_.c_str();
		pslError = PmSockSetConnectAddress(pChannel_, AF_INET, serverAddress, listenPort);
		UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockSetConnectAddress failed: ", pslError).c_str() );

		//with auto_ptr clientPeer instance will be destroyed in case an exception is thrown
		PeerBaseParams params(pGMain_, pChannel_, &config_, &pipeFd_);
		auto_ptr<PeerBase> apClientPeer;
		apClientPeer.reset(CreatePeer_(params) );
		apClientPeer->AppendToMyName("CLIENT");
		apClientPeer->Run();

		FN_PRINT_LINE("running main loop ...");
		g_main_loop_run(pGMain_->GetLoop() );

		//dealloc resources
		FN_PRINT_LINE(": main loop quit.");

	} catch (std::runtime_error& e) {
		//abort this test...
		pipeFd_.SendShutdownSignal();
	}

    return NULL; //will be returned by g_thread_join()
}


