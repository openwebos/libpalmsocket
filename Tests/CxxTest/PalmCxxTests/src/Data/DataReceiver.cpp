/*
 * DataReceiver.cpp
 *
 */


#define VERBOSE


#include <assert.h>


#include "DataReceiver.h"
#include "DataIn.h"
#include "Data.h"
#include "ConfigFile.h"
#include <cxxtest/TestSuite.h>
#include "CommonUtils.h"
#include "BandwidthMeter.h"
#include "DataAllocator.h"


DataReceiver::DataReceiver(const Config& config, const std::string& myName)
:myName_(myName)
,numBytesToReceive_(config.numberOfBytesToSend_)
,chunkSize_(config.chunkSize_)
,pChunk_(NULL)
{
	Init();
}


DataReceiver::DataReceiver(const unsigned int numBytesToReceive, const unsigned int chunkSize,
		const std::string& myName)
:myName_(myName)
,numBytesToReceive_(numBytesToReceive)
,chunkSize_(chunkSize)
{
	Init();
}


DataReceiver::~DataReceiver() {
	//pChunk_ should be NULL if all the data has been received
	assert( (IsFinished() && pChunk_==NULL) || !IsFinished() );

	//in case runtime_error is thrown, it may happen, that a DataReceiver instance will be destroyed in the middle
	//of a receive operation. In this case pChunk_ should be destroyed, too
	if (pChunk_!=NULL) {
		delete pChunk_;
	}

	if (pMeter_->WasUsed() ) {
		PRINT_LINE("%s received:%d bytes; speed:%4.4f bytes/sec %4.4f bits/sec", myName_.c_str(),
				totalBytesReceived_, pMeter_->GetBytesPerSecond(), pMeter_->GetBitsPerSecond() );
	}

	delete pMeter_;
	delete pAllocator_;
}


void DataReceiver::Init() {
	totalBytesReceived_=0;
	pMeter_ = new BandwidthMeter();
	pAllocator_ = new DataAllocator();
}


/*virtual*/
bool DataReceiver::IsFinished() {
	return totalBytesReceived_>=numBytesToReceive_;
}


/*virtual*/
void DataReceiver::Receive(GIOChannel *pChannel) {
	assert(totalBytesReceived_<numBytesToReceive_); //this does not validate data amount correctness, rather it's a warning not to call method by mistake, after all the data has been already received
	if (!pMeter_->IsStarted()) pMeter_->Start();

	if (pChunk_==NULL) {
		//last chunk was entirely received, allocate new one
		unsigned int numBytesRemaining = numBytesToReceive_ - totalBytesReceived_;
		unsigned int chunkSizeWithoutCRC = MIN(numBytesRemaining, chunkSize_);
		const unsigned int receivableChunkSize = Data::CalculateTotalSize(chunkSizeWithoutCRC);
		pChunk_ = new DataIn(receivableChunkSize, pAllocator_);
	}

	//read data
	bool isChunkFinishedReading=false;
	gsize numRead=0;
	GIOStatus gioStatus = pChunk_->Read(pChannel, &isChunkFinishedReading, &numRead);

	if (isChunkFinishedReading) {
		//all the chunk received
		PRINT_LINE("%s:   IN   bytes received:%d in %d iterations (+%d bytes CRC)",
				myName_.c_str(),
				(pChunk_->GetSize()-Data::CRC_SIZE),
				pChunk_->GetNumIterationsTaken(),
				Data::CRC_SIZE
		);
		totalBytesReceived_ += (pChunk_->GetSize()-Data::CRC_SIZE);
		TS_ASSERT(totalBytesReceived_<=numBytesToReceive_); //validate data amount correctness

		bool crcOK = pChunk_->CheckCRC();
		TS_ASSERT(crcOK); //validate quality

		delete pChunk_;
		pChunk_ = NULL;

	} else {
		//just part of the chunk received

	}

	if (totalBytesReceived_>=numBytesToReceive_) pMeter_->Stop(totalBytesReceived_);
}


unsigned int DataReceiver::GetTotalBytesReceived() {
	return totalBytesReceived_;
}




