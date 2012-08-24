/*
 * PeerFullDuplex.cpp
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


#include "PeerFullDuplex.h"
#include "GMain.h"
#include "CommonUtils.h"
#include "ConfigFile.h"
#include "DataSender.h"
#include <cxxtest/TestSuite.h>
#include "DataReceiver.h"


PeerFullDuplex::PeerFullDuplex(const PeerBaseParams& params, const std::string& myName)
:PeerBase(params, myName)
,pWatchOut_(NULL)
,pWatchIn_(NULL)
{
	pDataSender_ = new DataSender(config_, myName_ );
}


PeerFullDuplex::~PeerFullDuplex() {
	PRINT_LINE("%s               destructor ...", MyName() );
	//LOGVAR(pDataReceiver_->GetTotalBytesReceived() );

	delete pDataSender_;

	//detach from main loop in case it was not detached in callback, by returning false
	if (pWatchOut_) {
		g_source_destroy((GSource *)pWatchOut_); //according to glib documentation, detaches from main loop, if any.
		g_source_unref((GSource *)pWatchOut_); 	 //release our reference count
	}

	if (pWatchIn_) {
		g_source_destroy((GSource *)pWatchIn_);	//detach from main loop
		g_source_unref((GSource *)pWatchIn_); 	//release our reference count
	}
}


/*virtual*/
void PeerFullDuplex::OnConnect(PmSockIOChannel *pChannel, PslError errorCode) {
	UTIL_ASSERT_THROW_FATAL(!errorCode, MyName(), Err("PmSockConnectCrypto failed: ", errorCode).c_str() );

    //10. create a palmsock channel watch for IN
	CreateWatchWithCallback(pChannel, G_IO_IN, &pWatchIn_, (GSourceFunc)PeerBase::StaticChannelWatchOn_G_IO_IN,
			this, MyName() );

	//create watch for OUT
	CreateWatchWithCallback(pChannel, G_IO_OUT, &pWatchOut_, (GSourceFunc)PeerBase::StaticChannelWatchOn_G_IO_OUT,
			this, MyName() );
}


/*virtual*/
gboolean PeerFullDuplex::ChannelWatchOn_G_IO_IN(GIOChannel *pChannel, GIOCondition condition) {
	pDataReceiver_->Receive(pChannel);

	if (pDataSender_->IsFinished() && pDataReceiver_->IsFinished() ) {
		PRINT_LINE("%s will quit gmainloop ... ", MyName());
		g_main_loop_quit(gMain_.GetLoop());
	}

	bool staySubscribed = !pDataReceiver_->IsFinished();
	return staySubscribed;  //unsubscribe from event
}


gboolean PeerFullDuplex::ChannelWatchOn_G_IO_OUT(GIOChannel *pChannel, GIOCondition condition) {
	pDataSender_->Send(pChannel);

	if (pDataSender_->IsFinished() && pDataReceiver_->IsFinished() ) {
		PRINT_LINE("%s will quit gmainloop ... ", MyName());
		g_main_loop_quit(gMain_.GetLoop());
	}

	bool staySubscribed = !pDataSender_->IsFinished();
	return staySubscribed;
}



//typedef enum PslError_
//{
//    PSL_ERR_NONE                  = 0,
//    PSL_ERR_ACCESS                , /* Permission denied:e.g.,EACCES from bind()*/
//    PSL_ERR_ADDRINUSE             , /* Address already in use (EADDRINUSE) */
//    PSL_ERR_ADDRNOTAVAIL          , /* Can't bind to address (EADDRNOTAVAIL)*/
//    PSL_ERR_ALREADY               , /* Operation already in progress (EALREADY) */
//    PSL_ERR_BAD_SERV_ADDR         , /* Invalid server address */
//    PSL_ERR_BAD_BIND_ADDR         , /* Invalid local bind address */
//    PSL_ERR_FAILED                , /* Non-specific libpalmsocket error */
//    PSL_ERR_GETADDRINFO           , /* Can't resolve address */
//    PSL_ERR_INTR                  , /* Interrupted system call (EINTR) */
//    PSL_ERR_INVAL                 , /* Invalid argument (EINVAL) */
//    PSL_ERR_IO                    , /* EIO */
//    PSL_ERR_ISCONN                , /* Already connected (EISCONN) */
//    PSL_ERR_MEM                   , /* Out of memory (ENOMEM)*/
//    PSL_ERR_NOT_ALLOWED           , /* Operation not allowed in current state */
//    PSL_ERR_NOTCONN               , /* Not connected (ENOTCONN) */
//    PSL_ERR_OPENSSL               , /* Non-specific OPENSSL error value */
//    PSL_ERR_OVERFLOW              , /* EOVERFLOW */
//    PSL_ERR_PIPE                  , /* EPIPE */
//    PSL_ERR_SOCKET                , /* Error opening socket */
//    PSL_ERR_SOCKET_CONFIG         , /* Error configuring socket */
//    PSL_ERR_SSL_ALERT_UNKNOWN_CA  , /* TLS alert received: unknown CA */
//    PSL_ERR_SSL_BAD_EOF           , /* Unexpected, unclean SSL EOF */
//23    PSL_ERR_SSL_CERT_VERIFY       , /* SSL cert verification failed */
//    PSL_ERR_SSL_CONFIG            , /* SSL instance SSL_new or config failed */
//    PSL_ERR_SSL_CONNECT           , /* SSL connection attempt failed */
//    PSL_ERR_SSL_CTX               , /* Non-specific SSL CTX error value */
//    PSL_ERR_SSL_CLEAN_EOF         , /* 'Close notify' alert received from peer */
//    PSL_ERR_SSL_HOSTNAME_MISMATCH , /* Certificate does not match hostname */
//29    PSL_ERR_SSL_PROTOCOL          , /* Non-specific SSL protocol error */
//    PSL_ERR_SSL_SHUT_FAIL         , /* SSL shutdown failed */
//    PSL_ERR_SSL_WANT_READ         , /* Internal: waiting for readable sock */
//    PSL_ERR_SSL_WANT_WRITE        , /* Internal: waiting for writeable sock */
//    PSL_ERR_SYSCALL               , /* Non-specific system call failed */
//    PSL_ERR_TCP_CONNECT           , /* TCP/IP connection attempt failed */
//    PSL_ERR_TCP_CONNREFUSED       , /* ECONNREFUSED from connect() */
//    PSL_ERR_TCP_CONNRESET         , /* Connection reset by peer (ECONNRESET) */
//    PSL_ERR_TCP_CONN_AGAIN        , /* EAGAIN from connect(); see 'man connect' */
//    PSL_ERR_TCP_NETUNREACH        , /* ENETUNREACH */
//    PSL_ERR_TIMEDOUT              , /* ETIMEDOUT */
//    PSL_ERR_WOULDBLOCK            , /* Operation would block (EWOULDBLOCK) */
//
//
//    /// Not an actual error code: makes sure our Enum type is 'wide' enough for
//    /// future changes
//    PSL_ERR_reserved              = 0xFFFFFFFFUL
//} PslError;

