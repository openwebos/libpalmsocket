/*
 * DataSender.cpp
 *
 */


#define VERBOSE


#include <assert.h>


#include "DataSender.h"
#include "PeerBase.h"
#include "DataOut.h"
#include <cxxtest/TestSuite.h>
#include "CommonUtils.h"
#include "ConfigFile.h"
#include "DataAllocator.h"


DataSender::DataSender(const Config& config, const std::string& myName)
:myName_(myName)
,pChunk_(NULL)
,numberOfBytesToSend_(config.numberOfBytesToSend_)
,chunkSize_(config.chunkSize_)
{
	Init();
}


DataSender::DataSender(unsigned int numBytesToSend, unsigned int chunkSize, const std::string& myName)
:myName_(myName)
,pChunk_(NULL)
,numberOfBytesToSend_(numBytesToSend)
,chunkSize_(chunkSize)
{
	Init();
}


DataSender::~DataSender() {
	//pChunk_ should be NULL if all the data has been received
	assert(!IsFinished() || (IsFinished() && pChunk_==NULL));

	//in case runtime_error is thrown, it may happen, that a DataSender instance will be destroyed in the middle
	//of a send operation. In this case pChunk_ should be destroyed, too
	if (pChunk_!=NULL) {
		delete pChunk_;
	}

	delete pAllocator_;
}


void DataSender::Init() {
	numBytesSent_=0;
	pAllocator_ = new DataAllocator();
}


/*virtual*/
bool DataSender::IsFinished() {
	TS_ASSERT(numBytesSent_<=numberOfBytesToSend_); //validate data amount correctness
	return numBytesSent_==numberOfBytesToSend_;
}


/*virtual*/
void DataSender::Send(GIOChannel *pChannel) {
	if (numBytesSent_<numberOfBytesToSend_) {
		//not all sent yet

		if (pChunk_==NULL) {
			//last chunk was sent entirely
			unsigned int numBytesRemaining = numberOfBytesToSend_ - numBytesSent_;
			unsigned int sendableChunkSize = MIN(chunkSize_, numBytesRemaining);
			pChunk_ = new DataOut(sendableChunkSize, pAllocator_);
		}

		//send data
		bool isAllSent=false;
		gsize currentIterationBytesWritten=0;

		GIOStatus ioStatus = pChunk_->Send(pChannel, &isAllSent, &currentIterationBytesWritten);
		if (G_IO_STATUS_ERROR==ioStatus) {
			std::string errorMessage = "gioStatus = ";
			errorMessage.append(PmSockErrStringFromError(PmSockGetLastError((PmSockIOChannel *)pChannel)) );
			UTIL_THROW_FATAL(myName_.c_str(), errorMessage.c_str());
		}

		if (isAllSent) {
			//all the chunk was sent
			PRINT_LINE("%s:  OUT   bytes sent:%d in %d iterations", myName_.c_str(),
					pChunk_->GetSize(), pChunk_->GetNumIterationsTaken() );

			numBytesSent_ += (pChunk_->GetSize() - Data::CRC_SIZE);

			delete pChunk_;
			pChunk_=NULL;

		} else {
			//just part of the chunk was sent
			//do nothing
		}
	}
}


