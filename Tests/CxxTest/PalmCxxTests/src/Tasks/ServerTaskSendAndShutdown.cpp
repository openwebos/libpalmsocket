/*
 * ServerTaskSendAndShutdown.cpp
 *
 */


#define VERBOSE


#include "ServerTaskSendAndShutdown.h"
#include "CommonUtils.h"
#include "Data.h"
#include "GMain.h"
#include "Callback.h"
#include "cxxtest/TestSuite.h"


ServerTaskSendAndShutdown::ServerTaskSendAndShutdown(PmSockIOChannel *pChannel, const GMain& gMain,
		const std::string& myName)
:myName_(myName)
,pChannel_(pChannel)
,gMain_(gMain)
{
}


/*virtual */
void ServerTaskSendAndShutdown::Execute() {
	PRINT_LINE("sending 1 byte, shutting down ...");
	//send 1 byte
	char data=DEFERRED_SSL_SINGLE_BYTE_VALUE;
	gsize numBytesWritten=0;
	GIOStatus ioStatus = WriteBytesToChannel((GIOChannel *)pChannel_, &data, sizeof(data), &numBytesWritten);
	if (G_IO_STATUS_ERROR==ioStatus) {
		std::string errorMessage = "gioStatus = ";
		errorMessage.append(PmSockErrStringFromError(PmSockGetLastError(pChannel_)) );
		UTIL_THROW_FATAL(myName_.c_str(), errorMessage.c_str());
	}

	//initiate bidirectional shutdown
	PmSockSetUserData(pChannel_, dynamic_cast<ICryptoObserver *>(this));
	PslError pslError = PmSockShutCryptoTwoWay(pChannel_, /*pConf*/NULL, Callback<ICryptoObserver>);
	UTIL_ASSERT_THROW_FATAL(!pslError, myName_.c_str(),
			Err("PmSockShutCryptoTwoWay failed: ", pslError).c_str() );

	isFinished_=true;
}


/*virtual*/
void ServerTaskSendAndShutdown::OnShutCrypto(PmSockIOChannel *pChannel, PslError errorCode) {
	UTIL_ASSERT_THROW_FATAL(!errorCode, myName_.c_str(),
			Err("PmSockShutCryptoTwoWay failed: ", errorCode).c_str() );

	g_main_loop_quit(gMain_.GetLoop());
}
