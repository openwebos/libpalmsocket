/* @@@LICENSE
*
*      Copyright (c) 2009-2011 Hewlett-Packard Development Company, L.P.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

/*
 * ClientTasks.h
 *
 */

#ifndef CLIENTTASKS_H_
#define CLIENTTASKS_H_


#include "Task.h"
#include "GMain.h"
#include "Observer/IObserver.h"
#include "Observer/Callback.h"
#include "DataAllocator.h"


static const unsigned int NUM_BYTES_TO_READ_AT_ONCE=4000;


/**
 * Used by deferred SSL test, on client side
 * Receive 10 thousand bytes from server peer
 */
struct TaskReceive : public Task {
	DataIn *pChunk_;
	gsize chunkSize_;
	const std::string &myName_;
	PmSockIOChannel *pChannel_;
	unsigned int totalBytesReceived_;
	DataAllocator allocator_;

	TaskReceive(PmSockIOChannel *pChannel, const Config& config, const std::string& myName)
	:myName_(myName) {
		chunkSize_ = config.chunkSize_;
		pChannel_ = pChannel;
		totalBytesReceived_=0;
	}

	virtual ~TaskReceive() {
		assert(pChunk_==NULL);
	}

	virtual void Execute() {
		PRINT_LINE("Task_Receive");
		//receive 10 thousand bytes
		//because of the 5 sec delay on server side after the initial 10k was sent, all the 10k bytes will be received
		//on client side, the last one byte will be received separately.
		//so there is no possibility to read e.g in the following fashion: 4000 bytes; 4000 bytes; and 2001 bytes
		//instead: 4000 bytes; 4000 bytes; 2000 bytes; ..... 1 bytes;

		gsize numBytesReceivedDuringThisEvent=0;
		GIOStatus ioStatus = G_IO_STATUS_NORMAL;
		while (G_IO_STATUS_NORMAL==ioStatus
			&& totalBytesReceived_<ServerPeerDeferredSSL::NUM_BYTES_TO_SEND
			&& numBytesReceivedDuringThisEvent<NUM_BYTES_TO_READ_AT_ONCE)
		{
			gsize numBytesRemaining = ServerPeerDeferredSSL::NUM_BYTES_TO_SEND - totalBytesReceived_;
			gsize chunkSize = MIN(chunkSize_, numBytesRemaining);

			if (!pChunk_) {
				pChunk_ = new DataIn(chunkSize + Data::CRC_SIZE, &allocator_);
				//LOGVAR(chunkSize);
			}

			gsize numBytesRead=0;
			bool isChunkFinishedReading=false;
			ioStatus = pChunk_->Read((GIOChannel *)pChannel_, &isChunkFinishedReading, &numBytesRead);
			numBytesReceivedDuringThisEvent += numBytesRead;
			//LOGVAR(numBytesRead);

			if (isChunkFinishedReading) {
				bool crcOK=pChunk_->CheckCRC();
				TS_ASSERT(crcOK);

				totalBytesReceived_ += (pChunk_->GetSize()-Data::CRC_SIZE);
				delete pChunk_;
				pChunk_=NULL;
			}
		}

		PRINT_LINE("%s:   IN  Task_Receive bytes received:%d ", myName_.c_str(), numBytesReceivedDuringThisEvent);

		assert(totalBytesReceived_<=ServerPeerDeferredSSL::NUM_BYTES_TO_SEND);
		isFinished_= (totalBytesReceived_==ServerPeerDeferredSSL::NUM_BYTES_TO_SEND);
	}
};


/**
 * Used by deferred SSL test, on client side
 * Receive the last 1 byte, receive 'close notify', after that initiate a bidirectional shutdown
 */
class TaskShutdown : public Task, public ICryptoObserver {
	const std::string &myName_;
	PmSockIOChannel *pChannel_;
	const GMain& gMain_;

public:
	TaskShutdown(PmSockIOChannel *pChannel, const GMain& gMain, const std::string& myName)
	:myName_(myName)
	,gMain_(gMain)
	{
		pChannel_=pChannel;
	}

	virtual void Execute() {
		PRINT_LINE("Task_Shutdown");
		//receive some data, (it should be 1 single byte)
		const int nData=1024;
		char data[nData];
		gsize numBytesRead=0;
		GIOStatus ioStatus = ReadBytesFromChannel((GIOChannel *)pChannel_, &data, nData, &numBytesRead);

		if (ioStatus==G_IO_STATUS_AGAIN) return;

		TS_ASSERT(1==numBytesRead);
		TS_ASSERT(G_IO_STATUS_NORMAL==ioStatus);
		TS_ASSERT(DEFERRED_SSL_SINGLE_BYTE_VALUE==data[0]); //  check quality of received byte
		PRINT_LINE("%s %s", myName_.c_str(), IOStatusToString(ioStatus) );

		if (G_IO_STATUS_NORMAL==ioStatus) {
			PRINT_LINE("%s:   IN  Phase1 bytes received: %d ", myName_.c_str(), numBytesRead);
		}

		//read until EOF
		ioStatus=G_IO_STATUS_AGAIN;
		while (G_IO_STATUS_AGAIN==ioStatus) {
			ioStatus=ReadBytesFromChannel((GIOChannel *)pChannel_, &data, nData, &numBytesRead);
		}

		//initiate bidirectional shutdown
		if (G_IO_STATUS_EOF==ioStatus) {
			PmSockSetUserData(pChannel_, dynamic_cast<ICryptoObserver *>(this));
			PslError pslError = PmSockShutCryptoTwoWay(pChannel_, /*pConf*/NULL, Callback<ICryptoObserver>);
			UTIL_ASSERT_THROW_FATAL(!pslError, myName_.c_str(), Err("PmSockShutCryptoTwoWay failed: ", pslError).c_str());

		} else {
			assert(false);
		}

		//PRINT_LINE("%s %s", MyName(), IOStatusToString(ioStatus) );
	}

	/** ICryptoObserver */
	virtual void OnShutCrypto(PmSockIOChannel *pChannel, PslError errorCode) {
		UTIL_ASSERT_THROW_FATAL(!errorCode, myName_.c_str(), Err("PmSockShutCryptoTwoWay failed: ", errorCode).c_str());

		g_main_loop_quit(gMain_.GetLoop());
	}

private: //forbidden
	TaskShutdown(const TaskShutdown&);
	TaskShutdown& operator=(const TaskShutdown& );

};


#endif /* CLIENTTASKS_H_ */
