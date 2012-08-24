/*
 * ServerSetUp.cpp
 *
 */


#define VERBOSE


#include <iostream>
#include <string.h>
#include <palmsocket.h>


#include "ServerSetUp.h"
#include "SockUtils.h"
#include "ServerPeerHalfDuplexPlainIn.h"
#include "ThreadUtil.h"
#include "GMain.h"
#include "CommonUtils.h"
#include "ConfigFile.h"
#include "cxxtest/TestSuite.h"
#include "PipeFd.h"
#include "PeerBaseParams.h"
#include "Callback.h"


using namespace std;


/**
 * Makes a listening socket on specified port
 */
static int MakeListeningSock(int const port);


ServerSetUp::ServerSetUp(CreatePeerFunctionType Create, const Config& config, const PipeFd& pipeFd)
:SetupBase(Create, config, pipeFd, "ServerSetUp")
,listenSocket_(kSockUtilInvalidFD)
,pChannel_(NULL)
,pServerPeer_(NULL)
{
	//subscribe to thread shutdown event
	//ServerSetUp will wait in gmainloop for incoming connection on a channel
	//At this time a serverPeer (which would normally receive and handle a shutdown event) is not yet instanciated
	//If a fatal error occurs at this moment on client side (and this will send a thread shutdown event)
	//in this thread there is no one to handle this event. So ServerSetUp should listen to this event, too.

		//create GIOChannel
	pThreadShutdownNotifierChannel_ = g_io_channel_unix_new(pipeFd_.GetFdIn());
		//create GSource on GIOChannel
	pThreadShutdownWatch_ = g_io_create_watch(pThreadShutdownNotifierChannel_, G_IO_IN);
	g_source_set_can_recurse(pThreadShutdownWatch_, false);
	g_source_attach(pThreadShutdownWatch_, pGMain_->GetContext() );
		//attach this IThreadShutdownObserver to GSource
	Attach(this, pThreadShutdownWatch_);
}


/*virtual*/
ServerSetUp::~ServerSetUp() {
	FN_PRINT_LINE(" ");

	//destruction order: the opposite of construction order
	delete pServerPeer_;

	if (pChannel_) {
		g_io_channel_unref((GIOChannel *)pChannel_);
	}

	g_source_unref(pThreadShutdownWatch_);
	g_io_channel_unref(pThreadShutdownNotifierChannel_);
	//@todo jck g_source_destroy for pThreadShutdownWatch_
}


GThread * ServerSetUp::Start() {
	GThread *pThread = g_thread_create(&StaticThreadFunction<ServerSetUp>, this, /*joinable*/true, /* **error */ NULL);
	return pThread;
}


/**
 * this function will be called on 'listenEventSourceDispatchedOn_G_IO_IN' event source
 * (on G_IO_IN the source will be dispatched when there's data available for reading.)
 * gboolean (*GIOFunc) (GIOChannel *source, GIOCondition condition, gpointer data);
 */
static gboolean StaticListenChannelWatchOn_G_IO_IN(GIOChannel *source, GIOCondition condition, gpointer data) {
	return ((ServerSetUp *)data)->ListenChannelWatchOn_G_IO_IN();
}


gpointer ServerSetUp::ThreadFunction() {
	try {
		//2. open and configure a listening socket
		listenSocket_ = MakeListeningSock(config_.serverListenPort_);
		FN_PRINT_LINE("listenSocket_=%d", listenSocket_);

		//3. create and configure glib watch on listenSocket_
		GIOChannel *listenChannel = g_io_channel_unix_new(listenSocket_);
		GSource *listenWatch = g_io_create_watch(listenChannel, G_IO_IN);

		g_source_set_callback(listenWatch, (GSourceFunc)StaticListenChannelWatchOn_G_IO_IN, /*data*/this, /*notify*/NULL);
		g_source_attach(listenWatch, pGMain_->GetContext() );

		//4. run the server's gmain loop
		FN_PRINT_LINE("running main loop ... ");

		g_main_loop_run(pGMain_->GetLoop() );

		//dealloc resources
		g_source_destroy(listenWatch);
		g_io_channel_unref(listenChannel);
		close(listenSocket_);

		FN_PRINT_LINE(": main loop quit.");

	} catch (std::runtime_error& e) {
		//abort test...
		pipeFd_.SendShutdownSignal();
	}

	return 0; //will be returned by g_thread_join()
}


gboolean ServerSetUp::ListenChannelWatchOn_G_IO_IN() {
	//5. call accept
    struct sockaddr_in client;
    memset(&client, 0, sizeof(client));
    struct sockaddr *socketAddress = (struct sockaddr *)(&client);
    int clientSize = sizeof(client);
    socklen_t *socketLength = (socklen_t *)&clientSize;

    assert(listenSocket_!=kSockUtilInvalidFD);
    int connectedSocket = accept(listenSocket_, socketAddress, socketLength);

	FN_PRINT_LINE("Client with address %s and port %d connected", inet_ntoa(client.sin_addr), ntohs(client.sin_port) );

    if (connectedSocket < 0) {
        ::perror("accept(listenSock, NULL/*addr*/, 0/*addrlen*/) FAILED");
        g_main_loop_quit(pGMain_->GetLoop() );
        return false;
    }

    //6. Create palmsock thread context
	PmSockThreadContext *pThreadContext = NULL;

	PslError pslError = PmSockThreadCtxNewFromGMain(pGMain_->GetContext(), /*userLabel*/NULL, &pThreadContext);
	UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockThreadCtxNewFromGMain failed: ", pslError).c_str() );

    //7. Create palmsock channel
    assert(pChannel_==NULL);
    pslError = PmSockCreateChannel(pThreadContext, (PmSockOptionFlags)0, /*userLabel*/NULL, &pChannel_);

    //Release our reference to thread context
    ::PmSockThreadCtxUnref(pThreadContext);

    UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockCreateChannel failed: ", pslError).c_str() );

    //8. Associate the connected socket (the one returned from accept()) with the server's palmsock channel: PmSockSetConnectedFD()
    pslError = PmSockSetConnectedFD(pChannel_, connectedSocket, (PmSockFileDescOpts)0);
    UTIL_ASSERT_THROW_FATAL(!pslError, MyName(), Err("PmSockSetConnectFD failed: ", pslError).c_str() );

    assert(pServerPeer_==NULL);
	PeerBaseParams params(
		pGMain_,
		pChannel_,
		&config_,
		&pipeFd_
	);

	assert(CreatePeer_);
	pServerPeer_ = CreatePeer_(params);
    pServerPeer_->AppendToMyName("SERVER");
    pServerPeer_->Run(); //must exist until gmainloop exits

    //just one connection will be made during the whole lifetime of the server, so unsubscribe
    return false;
}


/*virtual*/
gboolean ServerSetUp::OnThreadShutdown(GIOChannel *pChannel, GIOCondition condition) {
	FN_PRINT_LINE("====================OnThreadShutdown() triggered");
	g_main_loop_quit(pGMain_->GetLoop());

	return false;
}


/**
 * non-member
 */


static int MakeListeningSock(int const port) {
    int s = kSockUtilInvalidFD;

    int const rc = sock_util_make_nb_listening_sock(AF_INET,
                                                    NULL/*addrStr*/,
                                                    port,
                                                    100/*listenQueueSize*/,
                                                    &s);
    if (rc) {
    	UTIL_THROW_FATAL("static function", (string("sock_util_make_nb_listening_sock: failed: ")+strerror(rc)).c_str() );
    }

    return s;
}

